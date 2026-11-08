package auth

import (
	"container/list"
	"crypto/rand"
	"maps"
	"net/http"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gorilla/securecookie"
	gorillasessions "github.com/gorilla/sessions"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// maxSessions bounds the entries that anonymous requests can add. Above it the
// oldest entry without a user goes, so a flood can break a login in progress but
// never ends a session that has a user.
const maxSessions = 10_000

type storedSession struct {
	id      string
	values  map[any]any
	expires time.Time
}

// memoryStore keeps sessions in process memory until they expire. Its cookie
// only holds the signed session ID.
type memoryStore struct {
	codec   securecookie.Codec
	options gorillasessions.Options

	mu      sync.Mutex
	entries map[string]*list.Element
	// Holds *storedSession, oldest save first. All entries have the same
	// lifetime, so this is also the order in which they expire.
	bySave list.List
}

// newSessionStore creates a server-side in-memory session store. Its key only
// signs the session ID. A restart ends every session anyway, so each store gets
// a new random key. rand.Read crashes the program if it cannot read, so there
// is no error to handle and no weak key to fall back to.
func newSessionStore(cfg SessionConfig) sessions.Store {
	key := make([]byte, 32)
	rand.Read(key)
	store := &memoryStore{
		codec:   securecookie.New(key, nil).MaxAge(cfg.MaxAge),
		entries: make(map[string]*list.Element),
	}
	store.Options(sessions.Options{
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		MaxAge:   cfg.MaxAge,
		Secure:   cfg.CookieSecure,
		HttpOnly: cfg.CookieHTTPOnly,
		SameSite: config.CookieSameSite(cfg.CookieSameSite).ToHTTP(),
	})
	return store
}

func (m *memoryStore) Options(options sessions.Options) {
	m.options = *options.ToGorillaOptions()
}

func (m *memoryStore) Get(r *http.Request, name string) (*gorillasessions.Session, error) {
	return gorillasessions.GetRegistry(r).Get(m, name)
}

// New loads a copy of the stored session. A cookie that fails the signature or
// age check gives an empty session and an error.
func (m *memoryStore) New(r *http.Request, name string) (*gorillasessions.Session, error) {
	session := gorillasessions.NewSession(m, name)
	options := m.options
	session.Options = &options
	session.IsNew = true

	cookie, err := r.Cookie(name)
	if err != nil {
		return session, nil
	}
	if err := m.codec.Decode(name, cookie.Value, &session.ID); err != nil {
		return session, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.entries[session.ID]; ok {
		session.Values = maps.Clone(entry.Value.(*storedSession).values)
		session.IsNew = false
	}
	return session, nil
}

// Save stores a copy of the session and writes its cookie. A negative MaxAge
// deletes the session instead.
func (m *memoryStore) Save(_ *http.Request, w http.ResponseWriter, s *gorillasessions.Session) error {
	value := ""
	if s.Options.MaxAge >= 0 {
		if s.ID == "" {
			s.ID = rand.Text()
		}
		var err error
		if value, err = m.codec.Encode(s.Name(), s.ID); err != nil {
			return err
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.entries[s.ID]; ok {
		m.remove(entry)
	}
	if s.Options.MaxAge >= 0 {
		now := time.Now()
		expires := now.Add(time.Duration(m.options.MaxAge) * time.Second)
		m.entries[s.ID] = m.bySave.PushBack(&storedSession{s.ID, maps.Clone(s.Values), expires})
		m.evict(now)
	}
	http.SetCookie(w, gorillasessions.NewCookie(s.Name(), value, s.Options))
	return nil
}

func (m *memoryStore) evict(now time.Time) {
	for e := m.bySave.Front(); e != nil && now.After(e.Value.(*storedSession).expires); e = m.bySave.Front() {
		m.remove(e)
	}
	// remove ends the loop too: a removed element has no next.
	for e := m.bySave.Front(); e != nil && len(m.entries) > maxSessions; e = e.Next() {
		if _, hasUser := e.Value.(*storedSession).values[sessKeyUserID]; !hasUser {
			m.remove(e)
		}
	}
}

func (m *memoryStore) remove(entry *list.Element) {
	delete(m.entries, m.bySave.Remove(entry).(*storedSession).id)
}

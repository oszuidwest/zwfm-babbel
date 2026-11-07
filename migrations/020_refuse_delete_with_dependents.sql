-- Refuse deleting a voice or station that gained a dependent row after the
-- service's dependency check, instead of silently clearing or removing that row.

ALTER TABLE stories DROP FOREIGN KEY stories_ibfk_1;
ALTER TABLE stories ADD CONSTRAINT stories_ibfk_1
    FOREIGN KEY (voice_id) REFERENCES voices(id) ON DELETE RESTRICT;

ALTER TABLE station_voices DROP FOREIGN KEY station_voices_ibfk_1;
ALTER TABLE station_voices ADD CONSTRAINT station_voices_ibfk_1
    FOREIGN KEY (station_id) REFERENCES stations(id) ON DELETE RESTRICT;

ALTER TABLE station_voices DROP FOREIGN KEY station_voices_ibfk_2;
ALTER TABLE station_voices ADD CONSTRAINT station_voices_ibfk_2
    FOREIGN KEY (voice_id) REFERENCES voices(id) ON DELETE RESTRICT;

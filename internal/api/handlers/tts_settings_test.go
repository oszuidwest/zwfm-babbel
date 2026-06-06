package handlers

import (
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestToTTSSettingsServiceRequest_SeedStates(t *testing.T) {
	seed := int64(42)

	tests := []struct {
		name          string
		req           utils.TTSSettingsUpdateRequest
		wantSeed      *int64
		wantClearSeed bool
	}{
		{
			name: "absent seed is ignored",
		},
		{
			name: "null seed clears",
			req: utils.TTSSettingsUpdateRequest{
				Seed: utils.Optional[int64]{Set: true},
			},
			wantClearSeed: true,
		},
		{
			name: "present seed updates",
			req: utils.TTSSettingsUpdateRequest{
				Seed: utils.Optional[int64]{Set: true, Value: &seed},
			},
			wantSeed: &seed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toTTSSettingsServiceRequest(tt.req)

			if got.ClearSeed != tt.wantClearSeed {
				t.Fatalf("ClearSeed = %t, want %t", got.ClearSeed, tt.wantClearSeed)
			}
			if tt.wantSeed == nil {
				if got.Seed != nil {
					t.Fatalf("Seed = %v, want nil", *got.Seed)
				}
				return
			}
			if got.Seed == nil || *got.Seed != *tt.wantSeed {
				t.Fatalf("Seed = %v, want %d", got.Seed, *tt.wantSeed)
			}
		})
	}
}

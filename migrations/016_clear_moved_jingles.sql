-- Before PUT refused pair changes on a station-voice with a jingle, a row
-- could move to another station or voice and keep audio_file named after its
-- old pair. Bulletins look the jingle up by the current pair, so they never
-- played that file, and deleting the row left it on disk.
--
-- Run this once after deploying a Babbel version that refuses those pair
-- changes and uploads whose pair changed. Running it again changes nothing.
--
-- Stop Babbel first and keep it stopped until the listed files are removed:
-- a running Babbel can recreate a listed pair and upload its jingle, which
-- the removal would then delete. Save the listing; a second run lists
-- nothing.
--
-- The SELECT lists the old-pair files that no station-voice owns after the
-- UPDATE. Remove them from the processed audio directory by hand. A file
-- named after a pair that a station-voice now owns is that row's jingle, and
-- a stored name that is not a jingle filename is not ours to remove, so
-- neither is listed.
SELECT DISTINCT sv.audio_file AS unused_jingle
FROM station_voices sv
WHERE sv.audio_file <> ''
  AND sv.audio_file <> CONCAT('station_', sv.station_id, '_voice_', sv.voice_id, '_jingle.wav')
  AND sv.audio_file REGEXP '^station_[0-9]+_voice_[0-9]+_jingle[.]wav$'
  AND NOT EXISTS (
    SELECT 1 FROM station_voices o
    WHERE CONCAT('station_', o.station_id, '_voice_', o.voice_id, '_jingle.wav') = sv.audio_file
  );

UPDATE station_voices
SET audio_file = ''
WHERE audio_file <> ''
  AND audio_file <> CONCAT('station_', station_id, '_voice_', voice_id, '_jingle.wav');

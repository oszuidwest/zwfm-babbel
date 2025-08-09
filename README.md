# Babbel

Headless REST API for generating audio news bulletins. Combines news stories with station jingles to create ready-to-air audio files.

## Overview

Babbel is a headless API-only system designed for integration with newsroom workflows and front-ends. It provides REST endpoints for managing stations, stories, and bulletin generation. No built-in UI - bring your own front-end or integrate directly with your systems.

Works with any radio automation that can fetch audio over HTTP and any newsroom system that can connect via REST/HTTP.

## Features

- **Headless API** - REST API designed for integration, no built-in UI
- **Single or multi-station** - Manage one or multiple stations
- **Station branding** - Custom jingles and audio identity per station
- **Story scheduling** - Air dates and weekday scheduling
- **Voice management** - Multiple newsreaders with station preferences
- **Audio processing** - FFmpeg-based mixing and normalization
- **Direct audio URLs** - Automation systems can fetch bulletins directly

## Installation

See [QUICKSTART.md](QUICKSTART.md) for installation instructions.

## Newsroom Workflow

1. **Setup**: Configure your stations and newsreaders
2. **Upload jingles**: Add station-specific intro/outro jingles
3. **Create stories**: Upload or POST news items with scheduling info
4. **Generate**: API creates bulletins with appropriate jingles
5. **Broadcast**: Automation systems fetch bulletins via HTTP

## Radio Automation Integration

Automation systems can fetch the latest bulletin directly:
```
GET /api/v1/stations/{station_id}/bulletins/latest/audio
```

Returns a WAV file ready for broadcast. Most automation systems can schedule HTTP audio downloads.

### Compatible Systems

- mAirList (HTTP audio source)
- RadioDJ (URL tracks)
- PlayoutONE (Network audio)
- StationPlaylist (Remote files)
- RTV AudioDownload Tool
- Any system that supports HTTP audio

## Requirements

- Docker and Docker Compose
- 2GB RAM minimum
- 20GB disk space
- Linux server recommended

## API Documentation

OpenAPI specification available in the Git repository and human-readable API docs in `/docs`.

## Development

```bash
git clone https://github.com/oszuidwest/zwfm-babbel.git
cd zwfm-babbel
docker-compose up -d
make test
```

## Tech Stack

- Go with Gin framework
- MySQL database
- FFmpeg for audio processing
- Docker for deployment

## License

MIT License - see [LICENSE](LICENSE) file.

## Credits

Developed by Streekomroep ZuidWest for newsroom operations across multiple local radio stations in the Netherlands.

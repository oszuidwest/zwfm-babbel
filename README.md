# Babbel

Audio bulletin generator for radio automation systems. Combines news stories with station-specific jingles to create ready-to-air bulletins.

## What it does

Babbel is an HTTP API that generates audio news bulletins. Upload news stories once, then generate bulletins with the right jingles for each radio station.

## Features

- Multiple radio stations with their own jingles and settings
- Story scheduling by date and weekday
- Automatic audio mixing with FFmpeg
- REST API for integration with automation systems
- Local auth or OAuth/OIDC (Microsoft, Google)
- Role-based access control

## Installation

See [QUICKSTART.md](QUICKSTART.md) for installation instructions.

For production deployment, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Usage

1. Create stations and voices (newsreaders)
2. Upload station-specific jingles
3. Upload news stories
4. Generate bulletins via API
5. Radio automation downloads bulletin audio

Example endpoint for radio automation:
```
GET /api/v1/stations/{id}/bulletins/latest/audio
```

## Requirements

- Docker and Docker Compose
- 2GB RAM minimum
- 20GB disk space

## Development

```bash
git clone https://github.com/oszuidwest/zwfm-babbel.git
cd zwfm-babbel
docker-compose up -d
make test
```

## API Documentation

OpenAPI specification available at `/docs` when running.

Full documentation in [docs/](docs/) directory.

## Tech Stack

- Go with Gin framework
- MySQL database
- FFmpeg for audio processing
- Docker for deployment

## License

MIT License - see [LICENSE](LICENSE) file.

## Support

- Issues: https://github.com/oszuidwest/zwfm-babbel/issues
- Security: security@zuidwest.nl

## Credits

Developed by ZuidWest FM, a local radio station in the Netherlands.
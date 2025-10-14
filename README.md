# ViduSec - Web Security Scanner

A comprehensive web security scanning tool with both command-line interface and modern web application.

## 🚀 Features

### Command Line Tool
- **Advanced Web Crawling** - Deep crawling with configurable depth and page limits
- **Endpoint Discovery** - Automatic discovery of GET, POST, and JavaScript API endpoints
- **Parameter Extraction** - Intelligent parameter extraction from forms, URLs, and JavaScript
- **Custom Headers** - Support for authenticated crawling with custom headers
- **Multiple Output Formats** - JSON, TXT, and structured data exports

### Web Application
- **User Authentication** - Secure registration and login system
- **Real-time Scanning** - Web-based interface for running security scans
- **Database Storage** - Persistent storage of scan results and user data
- **Dashboard** - Statistics and scan history management
- **Export Options** - Download results in various formats

## 📦 Installation

### Prerequisites
- Go 1.21 or later
- Git

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cybertron10/vidusec.git
   cd vidusec
   ```

2. **Install dependencies:**
   ```bash
   go mod tidy
   ```

3. **Build the command-line tool:**
   ```bash
   go build -o vidusec main.go
   ```

4. **Run the web application:**
   ```bash
   cd web
   chmod +x run.sh
   ./run.sh
   ```

## 🖥️ Command Line Usage

### Basic Crawling
```bash
# Simple crawl
./vidusec crawl https://example.com

# Advanced crawl with custom parameters
./vidusec crawl -depth 15 -pages 50000 -output results.txt https://example.com

# Crawl with custom headers
./vidusec crawl -headers "Authorization: Bearer token, X-Custom: value" https://example.com

# Crawl with headers from file
./vidusec crawl -headers-file auth.txt https://example.com
```

### Command Options
- `-depth int`: Maximum crawl depth (default: 10)
- `-pages int`: Maximum number of pages to crawl (default: 20000)
- `-output string`: Output file to save discovered URLs
- `-headers string`: Custom headers for authenticated crawling
- `-headers-file string`: File containing custom headers

### Output Files
The tool generates several output files:
- `scanning_data.json` - Structured data for XSS scanning
- `xss_endpoints.txt` - Endpoints formatted for XSS testing
- `customwordlist.txt` - Extracted parameters for wordlist generation

## 🌐 Web Application

### Access
Once running, open your browser and go to `http://localhost:8080`

### Features
1. **User Registration/Login** - Create an account to manage scans
2. **Start Scans** - Configure and run security scans through the web interface
3. **View Results** - Browse discovered endpoints and parameters
4. **Export Data** - Download results in JSON or TXT format
5. **Dashboard** - View scan statistics and history

### API Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/scanner/scan` - Start a new scan
- `GET /api/scanner/scans` - Get user's scans
- `GET /api/scanner/scans/:id/results` - Get scan results
- `GET /api/dashboard/stats` - Get dashboard statistics

## 🏗️ Architecture

### Command Line Tool
```
vidusec/
├── main.go                    # CLI entry point
├── internal/
│   ├── enhancedCrawler/      # Web crawling engine
│   ├── enhancedParamExtractor/ # Parameter extraction
│   └── scanningData/         # Data structuring
└── go.mod                    # Dependencies
```

### Web Application
```
vidusec/web/
├── main.go                   # Web server entry point
├── internal/
│   ├── api/                 # REST API handlers
│   ├── auth/                # Authentication service
│   ├── database/            # Database models
│   ├── middleware/          # HTTP middleware
│   └── scanner/             # Scanner service
├── templates/               # HTML templates
├── static/                  # CSS, JS, images
└── data/                    # Database and scan files
```

## 🔧 Development

### Building from Source
```bash
# Build CLI tool
go build -o vidusec main.go

# Build web application
cd web
go build -o vidusec-web main.go
```

### Running Tests
```bash
go test ./...
```

### Adding New Features
1. **CLI Features**: Add new commands in `main.go` and implement in `internal/`
2. **Web Features**: Add API endpoints in `web/internal/api/` and update frontend
3. **Scanner Features**: Extend crawler in `internal/enhancedCrawler/`

## 📊 Example Output

### Discovered Endpoints
```
GET | https://example.com/search?q=test | {"q": "test"} | - | {"User-Agent": "..."}
POST | https://example.com/login | {"username": "admin"} | {"username": "admin", "password": ""} | {"Content-Type": "application/x-www-form-urlencoded"}
JS | https://api.example.com/users | {"id": "123"} | - | {"Content-Type": "application/json"}
```

### Scan Statistics
```json
{
  "total_endpoints": 45,
  "get_count": 32,
  "post_count": 8,
  "js_count": 5,
  "total_parameters": 127
}
```

## 🚀 Deployment

### Docker
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o vidusec-web web/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/vidusec-web .
COPY --from=builder /app/web/templates ./templates
COPY --from=builder /app/web/static ./static
EXPOSE 8080
CMD ["./vidusec-web"]
```

### Cloud Platforms
- **AWS**: EC2, ECS, or Lambda
- **Google Cloud**: Cloud Run
- **Azure**: App Service
- **DigitalOcean**: Droplets

## 🔒 Security Considerations

- Use HTTPS in production
- Set strong JWT secrets
- Validate all user inputs
- Implement rate limiting
- Regular security updates

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/cybertron10/vidusec/issues)
- **Documentation**: Check the README files in each directory
- **API Docs**: Available at `/api/docs` when running the web application

## 🎯 Roadmap

- [ ] Vulnerability detection and reporting
- [ ] Integration with popular security tools
- [ ] Advanced filtering and search
- [ ] Team collaboration features
- [ ] API rate limiting and monitoring
- [ ] Multi-tenant support

---

**ViduSec** - Professional web security scanning made simple and accessible.

Made with ❤️ by [cybertron10](https://github.com/cybertron10)
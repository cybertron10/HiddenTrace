# ViduSec Web Application

A full-featured web security scanner with user authentication, database storage, and a modern web interface.

## Features

### 🔐 User Authentication
- User registration and login
- JWT-based authentication
- Secure password hashing
- Session management

### 🕷️ Advanced Web Crawling
- Configurable crawl depth and page limits
- Custom header support for authenticated crawling
- Form field discovery
- JavaScript API endpoint detection
- Hidden field extraction

### 📊 Scan Management
- Real-time scan progress tracking
- Scan history and results storage
- Export functionality (JSON, TXT, CSV)
- Dashboard with statistics

### 🎨 Modern Web Interface
- Responsive design with Tailwind CSS
- Real-time notifications
- Modal-based interactions
- Professional UI/UX

## Architecture

```
vidusec/web/
├── main.go                 # Main application entry point
├── internal/
│   ├── api/               # API handlers
│   ├── auth/              # Authentication service
│   ├── database/          # Database models and operations
│   ├── middleware/        # HTTP middleware
│   └── scanner/           # Scanner service integration
├── templates/             # HTML templates
├── static/               # Static assets (CSS, JS)
└── data/                 # Database and scan files
```

## Quick Start

### Prerequisites
- Go 1.21 or later
- SQLite (included with Go)

### Installation

1. **Clone and navigate to the web directory:**
   ```bash
   cd vidusec/web
   ```

2. **Install dependencies:**
   ```bash
   go mod tidy
   ```

3. **Run the application:**
   ```bash
   go run main.go
   ```

4. **Access the web interface:**
   Open your browser and go to `http://localhost:8080`

### First Steps

1. **Register a new account** or **login** with existing credentials
2. **Start a security scan** by clicking "Start Security Scan"
3. **Configure scan parameters:**
   - Target URL (required)
   - Max crawl depth (default: 10)
   - Max pages to crawl (default: 20,000)
   - Custom headers (optional)
4. **Monitor scan progress** and view results
5. **Export results** in various formats

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user profile

### Scanner
- `POST /api/scanner/scan` - Start a new scan
- `GET /api/scanner/scans` - Get user's scans
- `GET /api/scanner/scans/:id` - Get specific scan
- `GET /api/scanner/scans/:id/status` - Get scan status
- `GET /api/scanner/scans/:id/results` - Get scan results
- `GET /api/scanner/scans/:id/export` - Export scan results
- `DELETE /api/scanner/scans/:id` - Delete scan

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics

## Database Schema

### Users Table
- `id` - Primary key
- `username` - Unique username
- `email` - Unique email address
- `password_hash` - Bcrypt hashed password
- `created_at` - Account creation timestamp
- `updated_at` - Last update timestamp

### Scans Table
- `id` - Primary key
- `user_id` - Foreign key to users
- `target_url` - Target website URL
- `max_depth` - Maximum crawl depth
- `max_pages` - Maximum pages to crawl
- `status` - Scan status (pending, running, completed, failed)
- `progress` - Scan progress percentage
- `started_at` - Scan start time
- `completed_at` - Scan completion time
- `created_at` - Scan creation timestamp

### Scan Results Table
- `id` - Primary key
- `scan_id` - Foreign key to scans
- `endpoint_type` - Type of endpoint (get, post, js_api)
- `url` - Endpoint URL
- `method` - HTTP method
- `parameters` - JSON parameters
- `form_data` - JSON form data
- `headers` - JSON headers
- `description` - Endpoint description
- `created_at` - Result creation timestamp

## Configuration

### Environment Variables
- `PORT` - Server port (default: 8080)
- `JWT_SECRET` - JWT signing secret (default: hardcoded for development)

### Database
- SQLite database stored in `data/vidusec.db`
- Scan files stored in `data/scans/{scan_id}/`

## Development

### Project Structure
The application follows Go best practices with:
- Clean architecture separation
- Dependency injection
- Middleware pattern
- RESTful API design

### Adding New Features
1. **Database changes**: Update models in `internal/database/models.go`
2. **API endpoints**: Add handlers in `internal/api/handlers.go`
3. **Business logic**: Implement services in respective packages
4. **Frontend**: Update templates and JavaScript as needed

### Testing
```bash
# Run tests
go test ./...

# Run with coverage
go test -cover ./...
```

## Security Considerations

### Authentication
- JWT tokens with expiration
- Bcrypt password hashing
- Secure cookie settings
- CORS configuration

### Data Protection
- SQL injection prevention with parameterized queries
- Input validation and sanitization
- File system isolation for scan results
- User data isolation

### Production Deployment
- Use environment variables for secrets
- Enable HTTPS
- Configure proper CORS origins
- Set up database backups
- Monitor application logs

## Deployment Options

### Docker
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o vidusec-web main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/vidusec-web .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
EXPOSE 8080
CMD ["./vidusec-web"]
```

### Cloud Platforms
- **AWS**: EC2, ECS, or Lambda
- **Google Cloud**: Cloud Run or Compute Engine
- **Azure**: App Service or Container Instances
- **DigitalOcean**: Droplets or App Platform

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the API endpoints

---

**ViduSec Web** - Professional web security scanning made simple.

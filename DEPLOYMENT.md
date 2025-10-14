# ViduSec Deployment Guide

This guide covers various deployment options for the ViduSec web application.

## 🚀 Quick Start

### Local Development
```bash
# Clone the repository
git clone https://github.com/cybertron10/vidusec.git
cd vidusec

# Run the web application
cd web
chmod +x run.sh
./run.sh
```

Access at: `http://localhost:8080`

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)
```bash
# Clone and start
git clone https://github.com/cybertron10/vidusec.git
cd vidusec
docker-compose up -d

# With reverse proxy
docker-compose --profile proxy up -d
```

### Using Docker directly
```bash
# Build the image
docker build -t vidusec-web .

# Run the container
docker run -d \
  --name vidusec-web \
  -p 8080:8080 \
  -v vidusec_data:/app/data \
  vidusec-web
```

## ☁️ Cloud Deployment

### AWS EC2
1. **Launch EC2 instance** (Ubuntu 20.04 LTS recommended)
2. **Install Docker:**
   ```bash
   sudo apt update
   sudo apt install docker.io docker-compose
   sudo systemctl start docker
   sudo usermod -aG docker $USER
   ```

3. **Deploy application:**
   ```bash
   git clone https://github.com/cybertron10/vidusec.git
   cd vidusec
   docker-compose up -d
   ```

4. **Configure security group** to allow port 8080

### Google Cloud Run
```bash
# Build and push to Google Container Registry
gcloud builds submit --tag gcr.io/PROJECT-ID/vidusec-web

# Deploy to Cloud Run
gcloud run deploy vidusec-web \
  --image gcr.io/PROJECT-ID/vidusec-web \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

### DigitalOcean App Platform
1. Connect your GitHub repository
2. Select the `Dockerfile` in the root directory
3. Configure environment variables
4. Deploy

### Heroku
```bash
# Install Heroku CLI and login
heroku login

# Create app
heroku create your-vidusec-app

# Set buildpack
heroku buildpacks:set heroku/go

# Deploy
git push heroku main
```

## 🔧 Environment Configuration

### Environment Variables
```bash
# Server configuration
PORT=8080
NODE_ENV=production

# JWT configuration (for production)
JWT_SECRET=your-super-secret-jwt-key

# Database configuration (if using external DB)
DATABASE_URL=postgres://user:pass@host:port/dbname
```

### Production Security
1. **Set strong JWT secret:**
   ```bash
   export JWT_SECRET=$(openssl rand -base64 32)
   ```

2. **Enable HTTPS** with reverse proxy (nginx/traefik)

3. **Configure firewall** to restrict access

4. **Set up monitoring** and logging

## 📊 Monitoring and Maintenance

### Health Checks
The application includes built-in health checks:
- **Endpoint:** `GET /`
- **Docker health check:** Built into the container

### Logs
```bash
# Docker logs
docker logs vidusec-web

# Docker Compose logs
docker-compose logs -f vidusec-web
```

### Database Backup
```bash
# Backup SQLite database
cp data/vidusec.db backup-$(date +%Y%m%d).db

# Backup scan files
tar -czf scans-backup-$(date +%Y%m%d).tar.gz data/scans/
```

## 🔄 Updates and Maintenance

### Updating the Application
```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

### Database Migrations
The application automatically handles database schema updates on startup.

## 🛡️ Security Considerations

### Production Checklist
- [ ] Use HTTPS with valid SSL certificate
- [ ] Set strong JWT secret
- [ ] Configure proper CORS origins
- [ ] Enable firewall rules
- [ ] Regular security updates
- [ ] Monitor application logs
- [ ] Backup database regularly
- [ ] Use non-root user in containers

### Reverse Proxy Configuration (Nginx)
```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🚨 Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Find process using port 8080
sudo lsof -i :8080
# Kill the process
sudo kill -9 PID
```

**Database permission errors:**
```bash
# Fix data directory permissions
sudo chown -R 1001:1001 data/
```

**Docker build failures:**
```bash
# Clean Docker cache
docker system prune -a
# Rebuild without cache
docker build --no-cache -t vidusec-web .
```

### Performance Optimization
- Use SSD storage for database
- Configure appropriate memory limits
- Enable gzip compression in reverse proxy
- Use CDN for static assets

## 📞 Support

For deployment issues:
1. Check the logs: `docker-compose logs vidusec-web`
2. Verify environment variables
3. Check network connectivity
4. Review security group/firewall rules
5. Create an issue on GitHub

---

**Happy Deploying!** 🚀

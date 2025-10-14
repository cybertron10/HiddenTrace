// HiddenTrace Web Application JavaScript
class HiddenTraceApp {
    constructor() {
        this.apiBase = '/api';
        this.token = localStorage.getItem('HiddenTrace_token'); // Get JWT token
        this.isRedirecting = false; // Prevent multiple redirects
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.updateUI();
        this.checkAuth();
    }

    setupEventListeners() {
        // Navigation buttons
        document.getElementById('loginBtn').addEventListener('click', () => this.showLoginModal());
        document.getElementById('registerBtn').addEventListener('click', () => this.showRegisterModal());
        document.getElementById('dashboardBtn').addEventListener('click', () => this.goToDashboard());
        document.getElementById('logoutBtn').addEventListener('click', () => this.logout());
        document.getElementById('startScanBtn').addEventListener('click', () => this.showScanModal());
        document.getElementById('learnMoreBtn').addEventListener('click', () => this.scrollToFeatures());

        // Modal controls
        document.getElementById('closeLoginModal').addEventListener('click', () => this.hideLoginModal());
        document.getElementById('closeRegisterModal').addEventListener('click', () => this.hideRegisterModal());
        document.getElementById('closeScanModal').addEventListener('click', () => this.hideScanModal());
        document.getElementById('showRegisterModal').addEventListener('click', () => {
            this.hideLoginModal();
            this.showRegisterModal();
        });
        document.getElementById('showLoginModal').addEventListener('click', () => {
            this.hideRegisterModal();
            this.showLoginModal();
        });

        // Forms
        document.getElementById('loginForm').addEventListener('submit', (e) => this.handleLogin(e));
        document.getElementById('registerForm').addEventListener('submit', (e) => this.handleRegister(e));
        document.getElementById('scanForm').addEventListener('submit', (e) => this.handleScan(e));

        // Close modals on outside click
        document.getElementById('loginModal').addEventListener('click', (e) => {
            if (e.target.id === 'loginModal') this.hideLoginModal();
        });
        document.getElementById('registerModal').addEventListener('click', (e) => {
            if (e.target.id === 'registerModal') this.hideRegisterModal();
        });
        document.getElementById('scanModal').addEventListener('click', (e) => {
            if (e.target.id === 'scanModal') this.hideScanModal();
        });
    }

    updateUI() {
        const isAuthenticated = !!this.token;
        const loginBtn = document.getElementById('loginBtn');
        const registerBtn = document.getElementById('registerBtn');
        const userMenu = document.getElementById('userMenu');
        const startScanBtn = document.getElementById('startScanBtn');

        if (isAuthenticated) {
            loginBtn.style.display = 'none';
            registerBtn.style.display = 'none';
            userMenu.classList.remove('hidden');
            startScanBtn.textContent = 'Start New Scan';
        } else {
            loginBtn.style.display = 'block';
            registerBtn.style.display = 'block';
            userMenu.classList.add('hidden');
            startScanBtn.textContent = 'Start Security Scan';
        }
    }

    async checkAuth() {
        try {
            const response = await this.apiCall('/auth/me');
            if (response.ok) {
                const data = await response.json();
                this.user = data.user;
                this.updateUI();
            } else {
                // Don't call logout here to prevent redirect loops
                // Just clear the user state
                this.user = null;
                this.updateUI();
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            // Don't call logout here to prevent redirect loops
            // Just clear the user state
            this.user = null;
            this.updateUI();
        }
    }

    // API Helper
    async     apiCall(endpoint, options = {}) {
        const url = this.apiBase + endpoint;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            credentials: 'include', // Include cookies for session-based auth
            ...options
        };

        // Add Authorization header if token is available
        if (this.token) {
            config.headers['Authorization'] = `Bearer ${this.token}`;
        }

        return fetch(url, config);
    }

    // Authentication Methods
    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const response = await this.apiCall('/auth/login', {
                method: 'POST',
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                this.user = data.user;
                this.token = data.token; // Store JWT token
                localStorage.setItem('HiddenTrace_token', this.token); // Store in localStorage
                
                this.hideLoginModal();
                this.updateUI();
                this.showToast('Login successful! Redirecting to dashboard...', 'success');
                
                // Clear form
                document.getElementById('loginForm').reset();
                
                // Redirect to dashboard after a short delay
                setTimeout(() => {
                    this.goToDashboard();
                }, 1000);
            } else {
                this.showToast(data.error || 'Login failed', 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showToast('Network error. Please try again.', 'error');
        }
    }

    async handleRegister(e) {
        e.preventDefault();
        
        const username = document.getElementById('registerUsername').value;
        const email = document.getElementById('registerEmail').value;
        const password = document.getElementById('registerPassword').value;

        try {
            const response = await this.apiCall('/auth/register', {
                method: 'POST',
                body: JSON.stringify({ username, email, password })
            });

            const data = await response.json();

            if (response.ok) {
                this.user = data.user;
                this.token = data.token; // Store JWT token
                localStorage.setItem('HiddenTrace_token', this.token); // Store in localStorage
                
                this.hideRegisterModal();
                this.updateUI();
                this.showToast('Registration successful! Redirecting to dashboard...', 'success');
                
                // Clear form
                document.getElementById('registerForm').reset();
                
                // Redirect to dashboard after a short delay
                setTimeout(() => {
                    this.goToDashboard();
                }, 1000);
            } else {
                this.showToast(data.error || 'Registration failed', 'error');
            }
        } catch (error) {
            console.error('Registration error:', error);
            this.showToast('Network error. Please try again.', 'error');
        }
    }

    logout() {
        // Call logout API to invalidate session
        fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Authorization': `Bearer ${this.token}`
            }
        }).then(() => {
            // Clear token from localStorage
            localStorage.removeItem('HiddenTrace_token');
            this.user = null;
            this.token = null;
            this.updateUI();
            this.showToast('Logged out successfully', 'info');
        }).catch(() => {
            // Clear token from localStorage even if logout fails
            localStorage.removeItem('HiddenTrace_token');
            this.user = null;
            this.token = null;
            this.updateUI();
            this.showToast('Logged out successfully', 'info');
        });
        
        // Only redirect if not already redirecting
        if (!this.isRedirecting) {
            this.isRedirecting = true;
            // Small delay to allow toast to show
            setTimeout(() => {
                window.location.href = '/';
            }, 1000);
        }
    }

    // Scan Methods
    async handleScan(e) {
        e.preventDefault();
        
        if (!this.token) {
            this.showToast('Please login to start a scan', 'error');
            this.showLoginModal();
            return;
        }

        const targetUrl = document.getElementById('targetUrl').value;
        const maxDepth = parseInt(document.getElementById('maxDepth').value);
        const maxPages = parseInt(document.getElementById('maxPages').value);
        const customHeaders = document.getElementById('customHeaders').value;

        // Parse custom headers
        const headers = {};
        if (customHeaders.trim()) {
            customHeaders.split('\n').forEach(line => {
                const [key, ...valueParts] = line.split(':');
                if (key && valueParts.length > 0) {
                    headers[key.trim()] = valueParts.join(':').trim();
                }
            });
        }

        try {
            const response = await this.apiCall('/scanner/scan', {
                method: 'POST',
                body: JSON.stringify({
                    target_url: targetUrl,
                    max_depth: maxDepth,
                    max_pages: maxPages,
                    headers: headers
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.hideScanModal();
                this.showToast(`Scan started successfully! Scan ID: ${data.scan_id}`, 'success');
                this.goToDashboard();
                
                // Clear form
                document.getElementById('scanForm').reset();
            } else {
                this.showToast(data.error || 'Failed to start scan', 'error');
            }
        } catch (error) {
            console.error('Scan error:', error);
            this.showToast('Network error. Please try again.', 'error');
        }
    }

    // Navigation Methods
    goToDashboard() {
        // Navigate to the dashboard page
        window.location.href = '/dashboard';
    }

    scrollToFeatures() {
        document.querySelector('.py-20.bg-white').scrollIntoView({ 
            behavior: 'smooth' 
        });
    }

    // Modal Methods
    showLoginModal() {
        document.getElementById('loginModal').classList.remove('hidden');
    }

    hideLoginModal() {
        document.getElementById('loginModal').classList.add('hidden');
    }

    showRegisterModal() {
        document.getElementById('registerModal').classList.remove('hidden');
    }

    hideRegisterModal() {
        document.getElementById('registerModal').classList.add('hidden');
    }

    showScanModal() {
        if (!this.token) {
            this.showToast('Please login to start a scan', 'error');
            this.showLoginModal();
            return;
        }
        document.getElementById('scanModal').classList.remove('hidden');
    }

    hideScanModal() {
        document.getElementById('scanModal').classList.add('hidden');
    }

    // Toast Notification System
    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        
        const colors = {
            success: 'bg-green-500',
            error: 'bg-red-500',
            warning: 'bg-yellow-500',
            info: 'bg-blue-500'
        };

        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };

        toast.className = `${colors[type]} text-white px-6 py-3 rounded-lg shadow-lg mb-2 flex items-center max-w-sm`;
        toast.innerHTML = `
            <i class="${icons[type]} mr-2"></i>
            <span>${message}</span>
            <button class="ml-4 text-white hover:text-gray-200" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;

        toastContainer.appendChild(toast);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 5000);
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new HiddenTraceApp();
});

/**
 * Docker Utilities for Babbel API Tests
 * Handles Docker container management and service health checks
 */

const { execSync, spawn } = require('child_process');
const axios = require('axios');

class DockerUtils {
    constructor(baseTest) {
        this.baseTest = baseTest;
        this.apiBase = baseTest.apiBase;
    }
    
    /**
     * Check dependencies (Docker, docker-compose, etc.)
     */
    checkDependencies() {
        this.baseTest.printSection('Checking Dependencies');
        
        const requiredTools = ['curl', 'docker', 'docker-compose'];
        const missing = [];
        
        for (const tool of requiredTools) {
            try {
                execSync(`which ${tool}`, { stdio: 'pipe' });
            } catch (error) {
                missing.push(tool);
            }
        }
        
        if (missing.length > 0) {
            this.baseTest.printError(`Missing required tools: ${missing.join(', ')}`);
            return false;
        }
        
        // Check if FFmpeg is available
        try {
            execSync('which ffmpeg', { stdio: 'pipe' });
        } catch (error) {
            this.baseTest.printError('FFmpeg not found. Please install FFmpeg.');
            return false;
        }
        
        // Check if we're in the project root
        try {
            execSync('ls docker-compose.yml', { stdio: 'pipe', cwd: process.cwd().replace('/tests', '') });
        } catch (error) {
            this.baseTest.printError('docker-compose.yml not found. Please run from project root.');
            return false;
        }
        
        this.baseTest.printSuccess('All dependencies available');
        return true;
    }
    
    /**
     * Start Docker services with full clean rebuild
     */
    async startDocker() {
        this.baseTest.printSection('Starting Docker Services (Full Clean Rebuild)');
        
        const projectRoot = process.cwd().replace('/tests', '');
        
        try {
            this.baseTest.printInfo('Step 1/5: Stopping existing containers...');
            execSync('docker-compose down -v --remove-orphans', { 
                stdio: 'pipe', 
                cwd: projectRoot 
            });
            this.baseTest.printSuccess('✓ Containers stopped and removed');
            
            this.baseTest.printInfo('Step 2/5: Removing volumes and networks...');
            execSync('docker-compose rm -f -s -v', { 
                stdio: 'pipe', 
                cwd: projectRoot 
            });
            execSync('docker volume prune -f', { stdio: 'pipe' });
            this.baseTest.printSuccess('✓ Volumes and networks cleaned');
            
            this.baseTest.printInfo('Step 3/5: Removing old images...');
            try {
                execSync('docker rmi oszw-zwfm-babbel-babbel:latest', { stdio: 'pipe' });
            } catch (error) {
                // Image might not exist, that's fine
            }
            try {
                execSync('docker rmi oszw-zwfm-babbel-mysql:latest', { stdio: 'pipe' });
            } catch (error) {
                // Image might not exist, that's fine
            }
            this.baseTest.printSuccess('✓ Old images removed');
            
            this.baseTest.printInfo('Step 4/5: Building fresh images (this may take a minute)...');
            execSync('docker-compose build --no-cache', { 
                stdio: 'pipe', 
                cwd: projectRoot 
            });
            this.baseTest.printSuccess('✓ Fresh images built successfully');
            
            this.baseTest.printInfo('Step 5/5: Starting fresh containers...');
            execSync('docker-compose up -d', { 
                stdio: 'pipe', 
                cwd: projectRoot 
            });
            this.baseTest.printSuccess('✓ Docker containers started');
            
            // Wait for services to be ready
            this.baseTest.printInfo('Waiting for services to be ready...');
            await new Promise(resolve => setTimeout(resolve, 10000));
            
            // Check if API is responding
            let retries = 0;
            while (retries < 30) {
                try {
                    await axios.get(`${this.apiBase}/health`, { timeout: 2000 });
                    this.baseTest.printSuccess('API is responding');
                    return true;
                } catch (error) {
                    await new Promise(resolve => setTimeout(resolve, 2000));
                    retries++;
                }
            }
            
            this.baseTest.printError('API failed to start within timeout');
            return false;
            
        } catch (error) {
            this.baseTest.printError(`Docker startup failed: ${error.message}`);
            try {
                // Show docker-compose logs for debugging
                const logs = execSync('docker-compose logs --tail=50', { 
                    encoding: 'utf8', 
                    cwd: projectRoot 
                });
                console.error(logs);
            } catch (logError) {
                // Ignore log errors
            }
            return false;
        }
    }
    
    /**
     * Initialize test environment (database setup and initial login)
     */
    async initializeEnvironment() {
        this.baseTest.printSection('Initializing Test Environment');
        
        // Reset test counters
        this.baseTest.resetTestCounters();
        
        // Clean audio directories
        this.cleanAudio();
        
        // Initialize database
        try {
            const projectRoot = process.cwd().replace('/tests', '');
            execSync('bash tests/setup/database.sh setup', { 
                stdio: 'inherit', 
                cwd: projectRoot 
            });
            this.baseTest.printSuccess('Database initialized');
        } catch (error) {
            this.baseTest.printError('Database initialization failed');
            return false;
        }
        
        // Initial admin login
        if (await this.baseTest.apiLogin()) {
            this.baseTest.printSuccess('Initial authentication successful');
            return true;
        } else {
            this.baseTest.printError('Initial authentication failed');
            return false;
        }
    }
    
    /**
     * Clean audio files
     */
    cleanAudio() {
        this.baseTest.printSection('Cleaning Audio Files');
        
        const audioDir = this.baseTest.audioDir;
        
        try {
            // Create audio directories if they don't exist
            execSync(`mkdir -p ${audioDir}/processed ${audioDir}/output ${audioDir}/stories`, { stdio: 'pipe' });
            
            // Remove existing generated files
            execSync(`rm -f ${audioDir}/output/*.wav`, { stdio: 'pipe' });
            execSync(`rm -f ${audioDir}/processed/station_*_voice_*_jingle.wav`, { stdio: 'pipe' });
            
            this.baseTest.printSuccess('Audio directories cleaned');
        } catch (error) {
            this.baseTest.printWarning(`Audio cleanup warning: ${error.message}`);
        }
    }
    
    /**
     * Simple download function
     */
    async simpleDownload(url, outputFile) {
        this.baseTest.printInfo(`Downloading: ${url}`);
        
        try {
            const response = await axios({
                method: 'get',
                url: url,
                responseType: 'stream',
                timeout: 30000
            });
            
            if (response.status === 200) {
                const fs = require('fs');
                const writer = fs.createWriteStream(outputFile);
                response.data.pipe(writer);
                
                return new Promise((resolve, reject) => {
                    writer.on('finish', () => {
                        this.baseTest.printSuccess('Download successful');
                        resolve(true);
                    });
                    writer.on('error', reject);
                });
            } else {
                this.baseTest.printError(`Download failed with HTTP ${response.status}`);
                return false;
            }
        } catch (error) {
            this.baseTest.printError(`Download failed: ${error.message}`);
            try {
                const fs = require('fs');
                fs.unlinkSync(outputFile);
            } catch (e) {
                // Ignore cleanup errors
            }
            return false;
        }
    }
}

module.exports = DockerUtils;
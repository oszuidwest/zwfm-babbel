#!/usr/bin/env node

/**
 * Babbel Test Suite - Node.js Orchestrator
 * Runs all tests in the correct order
 */

const { spawn } = require('child_process');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs');

class TestOrchestrator {
    constructor() {
        // Test suites configuration
        this.availableSuites = [
            'auth', 'permissions', 'stations', 
            'voices', 'station-voices', 'stories', 
            'bulletins', 'users', 'validation'
        ];
        
        // Test suite order (ensures dependencies are met)
        this.testOrder = [
            'auth', 'permissions', 'stations',
            'voices', 'station-voices', 'stories',
            'bulletins', 'users', 'validation'
        ];
        
        // Test suite scripts
        this.suiteScripts = {
            'auth': './auth/test-auth.js',
            'permissions': './auth/test-permissions.js',
            'stations': './stations/test-stations.js',
            'voices': './voices/test-voices.js',
            'station-voices': './station-voices/test-station-voices.js',
            'stories': './stories/test-stories.js',
            'bulletins': './bulletins/test-bulletins.js',
            'users': './users/test-users.js',
            'validation': './validation/validation-tests.js'
        };
        
        // Global test tracking
        this.totalTests = 0;
        this.passedTests = 0;
        this.failedTests = 0;
        this.suitesRun = 0;
        this.suitesPassed = 0;
        this.suitesFailed = 0;
        
        // Parse command line arguments
        this.args = process.argv.slice(2);
        this.options = {
            quick: this.args.includes('--quick'),
            noDocker: this.args.includes('--no-docker'),
            noSetup: this.args.includes('--no-setup'),
            help: this.args.includes('--help') || this.args.includes('-h')
        };
        
        // Get specific test suites to run
        this.suitesToRun = this.args.filter(arg => !arg.startsWith('--') && arg !== '-h');
    }
    
    printHeader(text) {
        console.log(chalk.magenta.bold('═'.repeat(60)));
        console.log(chalk.magenta.bold(`  ${text}`));
        console.log(chalk.magenta.bold('═'.repeat(60)));
        console.log();
    }
    
    printSection(text) {
        console.log();
        console.log(chalk.cyan(`━━━ ${text} ━━━`));
    }
    
    printSuccess(text) {
        console.log(chalk.green(`✓ ${text}`));
    }
    
    printError(text) {
        console.log(chalk.red(`✗ ${text}`));
    }
    
    printInfo(text) {
        console.log(chalk.yellow(`ℹ ${text}`));
    }
    
    showHelp() {
        console.log(`
${chalk.bold('Usage:')} node run-all.js [options] [test-suite...]

${chalk.bold('Options:')}
  --quick         Skip Docker and database setup
  --no-docker     Skip Docker management
  --no-setup      Skip database setup
  -h, --help      Show this help message

${chalk.bold('Test Suites:')}
  ${this.availableSuites.join(', ')}

${chalk.bold('Examples:')}
  node run-all.js                   # Run all tests
  node run-all.js auth              # Run only auth tests
  node run-all.js auth stations     # Run auth and stations tests
  node run-all.js --quick           # Run all tests without setup
`);
    }
    
    /**
     * Run Docker setup
     */
    async runDockerSetup() {
        if (this.options.noDocker || this.options.quick) {
            this.printInfo('Skipping Docker setup (--no-docker or --quick)');
            return true;
        }
        
        this.printSection('Starting Docker Services');
        
        return new Promise((resolve) => {
            const proc = spawn('docker-compose', ['up', '-d'], {
                cwd: path.join(__dirname, '..'),
                stdio: 'inherit'
            });
            
            proc.on('close', (code) => {
                if (code === 0) {
                    this.printSuccess('Docker services started');
                    // Wait for services to be ready
                    setTimeout(() => resolve(true), 5000);
                } else {
                    this.printError('Failed to start Docker services');
                    resolve(false);
                }
            });
        });
    }
    
    /**
     * Run database setup
     */
    async runDatabaseSetup() {
        if (this.options.noSetup || this.options.quick) {
            this.printInfo('Skipping database setup (--no-setup or --quick)');
            return true;
        }
        
        this.printSection('Setting Up Database');
        
        // Run the setup test which handles database initialization
        return await this.runTestFile('./auth/test-auth.js', true);
    }
    
    /**
     * Run a single test file
     */
    async runTestFile(scriptPath, setupOnly = false) {
        const fullPath = path.join(__dirname, scriptPath);
        
        if (!fs.existsSync(fullPath)) {
            this.printError(`Test file not found: ${fullPath}`);
            return false;
        }
        
        return new Promise((resolve) => {
            const env = { ...process.env };
            if (setupOnly) {
                env.SETUP_ONLY = 'true';
            }
            
            const proc = spawn('node', [fullPath], {
                cwd: __dirname,
                env: env,
                stdio: 'pipe'
            });
            
            let output = '';
            let hasErrors = false;
            
            proc.stdout.on('data', (data) => {
                const text = data.toString();
                output += text;
                process.stdout.write(text);
            });
            
            proc.stderr.on('data', (data) => {
                const text = data.toString();
                output += text;
                process.stderr.write(text);
            });
            
            proc.on('close', (code) => {
                // Parse test results from output
                const passedMatch = output.match(/✓ Passed:\s*(\d+)/);
                const failedMatch = output.match(/✗ Failed:\s*(\d+)/);
                
                if (passedMatch) {
                    this.passedTests += parseInt(passedMatch[1]);
                    this.totalTests += parseInt(passedMatch[1]);
                }
                if (failedMatch) {
                    this.failedTests += parseInt(failedMatch[1]);
                    this.totalTests += parseInt(failedMatch[1]);
                }
                
                if (code === 0) {
                    this.suitesPassed++;
                    resolve(true);
                } else {
                    this.suitesFailed++;
                    resolve(false);
                }
            });
        });
    }
    
    /**
     * Run a test suite
     */
    async runTestSuite(suiteName) {
        const scriptPath = this.suiteScripts[suiteName];
        if (!scriptPath) {
            this.printError(`Unknown test suite: ${suiteName}`);
            return false;
        }
        
        this.printHeader(`Running Test Suite: ${suiteName}`);
        this.suitesRun++;
        
        return await this.runTestFile(scriptPath);
    }
    
    /**
     * Main orchestration logic
     */
    async run() {
        this.printHeader('BABBEL TEST SUITE ORCHESTRATOR');
        
        // Show help if requested
        if (this.options.help) {
            this.showHelp();
            process.exit(0);
        }
        
        // Setup phase
        if (!this.options.quick) {
            if (!await this.runDockerSetup()) {
                this.printError('Docker setup failed');
                process.exit(1);
            }
            
            if (!await this.runDatabaseSetup()) {
                this.printError('Database setup failed');
                process.exit(1);
            }
        }
        
        // Determine which suites to run
        let suitesToRun = this.suitesToRun.length > 0 ? this.suitesToRun : this.testOrder;
        
        // Validate suite names
        for (const suite of suitesToRun) {
            if (!this.availableSuites.includes(suite)) {
                this.printError(`Unknown test suite: ${suite}`);
                this.showHelp();
                process.exit(1);
            }
        }
        
        // Run test suites
        for (const suite of suitesToRun) {
            if (!await this.runTestSuite(suite)) {
                this.printInfo(`Suite ${suite} had failures`);
            }
        }
        
        // Print final summary
        this.printHeader('TEST SUMMARY');
        console.log(chalk.bold('Test Suites:'));
        console.log(chalk.green(`  ✓ Passed: ${this.suitesPassed}`));
        console.log(chalk.red(`  ✗ Failed: ${this.suitesFailed}`));
        console.log(chalk.cyan(`  Total: ${this.suitesRun}`));
        console.log();
        console.log(chalk.bold('Individual Tests:'));
        console.log(chalk.green(`  ✓ Passed: ${this.passedTests}`));
        console.log(chalk.red(`  ✗ Failed: ${this.failedTests}`));
        console.log(chalk.cyan(`  Total: ${this.totalTests}`));
        
        if (this.suitesFailed === 0 && this.failedTests === 0) {
            console.log();
            console.log(chalk.green.bold('All tests passed! 🎉'));
            process.exit(0);
        } else {
            console.log();
            console.log(chalk.red.bold('Some tests failed.'));
            process.exit(1);
        }
    }
}

// Run the orchestrator
const orchestrator = new TestOrchestrator();
orchestrator.run().catch(error => {
    console.error(chalk.red('Fatal error:'), error);
    process.exit(1);
});
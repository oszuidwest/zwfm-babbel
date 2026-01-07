#!/usr/bin/env node

// Babbel test suite orchestrator.
// Runs all test suites in the correct order with comprehensive reporting.

const { spawn } = require('child_process');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs');

// Force color support for terminals that support it but aren't auto-detected by chalk.
if (!chalk.supportsColor && (process.env.TERM && process.env.TERM.includes('color'))) {
    process.env.FORCE_COLOR = '1';
    // Re-import chalk to pick up the updated environment variable.
    delete require.cache[require.resolve('chalk')];
    const chalkModule = require('chalk');
    Object.assign(chalk, chalkModule);
}

class TestOrchestrator {
    constructor() {
        // Configuration for available test suites.
        this.availableSuites = [
            'auth', 'permissions', 'stations',
            'voices', 'station-voices', 'stories',
            'bulletins', 'automation', 'users', 'validation'
        ];

        // Execution order ensures dependencies are met.
        this.testOrder = [
            'auth', 'permissions', 'stations',
            'voices', 'station-voices', 'stories',
            'bulletins', 'automation', 'users', 'validation'
        ];

        // Mapping of suite names to their script paths.
        this.suiteScripts = {
            'auth': './auth/test-auth.js',
            'permissions': './auth/test-permissions.js',
            'stations': './stations/test-stations.js',
            'voices': './voices/test-voices.js',
            'station-voices': './station-voices/test-station-voices.js',
            'stories': './stories/test-stories.js',
            'bulletins': './bulletins/test-bulletins.js',
            'automation': './automation/test-automation.js',
            'users': './users/test-users.js',
            'validation': './validation/validation-tests.js'
        };
        
        // Global counters for test result tracking.
        this.totalTests = 0;
        this.passedTests = 0;
        this.failedTests = 0;
        this.suitesRun = 0;
        this.suitesPassed = 0;
        this.suitesFailed = 0;
        
        // Process command line arguments for configuration.
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
        console.error(chalk.magenta.bold('═'.repeat(60)));
        console.error(chalk.magenta.bold(`  ${text}`));
        console.error(chalk.magenta.bold('═'.repeat(60)));
        console.error();
    }
    
    printSection(text) {
        console.error();
        console.error(chalk.cyan(`━━━ ${text} ━━━`));
    }
    
    printSuccess(text) {
        console.error(chalk.green(`✓ ${text}`));
    }
    
    printError(text) {
        console.error(chalk.red(`✗ ${text}`));
    }
    
    printInfo(text) {
        console.error(chalk.yellow(`ℹ ${text}`));
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

        // First, stop and remove volumes for clean state
        this.printSection('Cleaning Docker Environment');
        await new Promise((resolve) => {
            const proc = spawn('docker', ['compose', 'down', '-v'], {
                cwd: path.join(__dirname, '..'),
                stdio: 'inherit'
            });
            proc.on('close', () => resolve());
        });

        // Build with fresh code
        this.printSection('Building Docker Image');
        const buildSuccess = await new Promise((resolve) => {
            const proc = spawn('docker', ['compose', 'build'], {
                cwd: path.join(__dirname, '..'),
                stdio: 'inherit'
            });
            proc.on('close', (code) => {
                if (code === 0) {
                    this.printSuccess('Docker image built');
                    resolve(true);
                } else {
                    this.printError('Failed to build Docker image');
                    resolve(false);
                }
            });
        });

        if (!buildSuccess) {
            return false;
        }

        this.printSection('Starting Docker Services');

        return new Promise((resolve) => {
            const proc = spawn('docker', ['compose', 'up', '-d'], {
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
            // Ensure color support is passed to child processes
            if (process.env.FORCE_COLOR) {
                env.FORCE_COLOR = process.env.FORCE_COLOR;
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
                // Parse test results from output - look for the last occurrence
                const matches = [...output.matchAll(/✓ Passed:\s*(\d+)[\s\S]*?✗ Failed:\s*(\d+)/g)];
                
                if (matches.length > 0) {
                    // Use the last match (the summary)
                    const lastMatch = matches[matches.length - 1];
                    const passed = parseInt(lastMatch[1]);
                    const failed = parseInt(lastMatch[2]);
                    
                    this.passedTests += passed;
                    this.failedTests += failed;
                    this.totalTests += (passed + failed);
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
        console.error(chalk.bold('Test Suites:'));
        console.error(chalk.green(`  ✓ Passed: ${this.suitesPassed}`));
        console.error(chalk.red(`  ✗ Failed: ${this.suitesFailed}`));
        console.error(chalk.cyan(`  Total: ${this.suitesRun}`));
        console.error();
        console.error(chalk.bold('Individual Tests:'));
        console.error(chalk.green(`  ✓ Passed: ${this.passedTests}`));
        console.error(chalk.red(`  ✗ Failed: ${this.failedTests}`));
        console.error(chalk.cyan(`  Total: ${this.totalTests}`));
        
        if (this.suitesFailed === 0 && this.failedTests === 0) {
            console.error();
            console.error(chalk.green.bold('All tests passed!'));
            process.exit(0);
        } else {
            console.error();
            console.error(chalk.red.bold('Some tests failed.'));
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
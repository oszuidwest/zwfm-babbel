#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * Script to check the migration status of bash tests to Node.js
 */

function extractBashTests(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const testFunctions = [];
        
        // Match test functions (test_* or function test_*)
        const regex = /(?:^|\n)(?:function\s+)?(test_\w+)\s*\(\)/gm;
        let match;
        while ((match = regex.exec(content)) !== null) {
            testFunctions.push(match[1]);
        }
        
        return testFunctions;
    } catch (error) {
        return [];
    }
}

function extractNodeTests(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const testFunctions = [];
        
        // Match async test methods
        const regex = /async\s+(test\w+)\s*\(/gm;
        let match;
        while ((match = regex.exec(content)) !== null) {
            testFunctions.push(match[1]);
        }
        
        return testFunctions;
    } catch (error) {
        return [];
    }
}

function compareTests(bashTests, nodeTests) {
    // Convert bash test names to Node.js style (test_foo_bar -> testFooBar)
    const bashTestsConverted = bashTests.map(name => {
        return name.replace(/^test_/, 'test')
            .replace(/_([a-z])/g, (m, p1) => p1.toUpperCase())
            .replace(/^test/, 'test')
            .replace(/^test([a-z])/, (m, p1) => 'test' + p1.toUpperCase());
    });
    
    const missing = [];
    const implemented = [];
    
    bashTestsConverted.forEach((test, index) => {
        if (nodeTests.includes(test)) {
            implemented.push({ bash: bashTests[index], node: test });
        } else {
            // Check for similar names
            const similar = nodeTests.find(nt => 
                nt.toLowerCase() === test.toLowerCase() ||
                nt.toLowerCase().includes(test.toLowerCase().replace('test', ''))
            );
            if (similar) {
                implemented.push({ bash: bashTests[index], node: similar });
            } else {
                missing.push({ bash: bashTests[index], expectedNode: test });
            }
        }
    });
    
    const extra = nodeTests.filter(nt => 
        !implemented.some(i => i.node === nt)
    );
    
    return { missing, implemented, extra };
}

function checkTestSuite(suiteName) {
    const bashPath = path.join(__dirname, suiteName, `test-${suiteName}.sh`);
    const nodePath = path.join(__dirname, suiteName, `test-${suiteName}.js`);
    
    if (!fs.existsSync(bashPath)) {
        return null;
    }
    
    const bashTests = extractBashTests(bashPath);
    const nodeTests = fs.existsSync(nodePath) ? extractNodeTests(nodePath) : [];
    
    return {
        suite: suiteName,
        bashPath,
        nodePath,
        bashTests,
        nodeTests,
        comparison: compareTests(bashTests, nodeTests)
    };
}

// Test suites to check
const testSuites = [
    'auth',
    'permissions',
    'stations',
    'voices',
    'station-voices',
    'stories',
    'bulletins',
    'users',
    'validation'
];

console.log('Babbel Test Migration Status Check');
console.log('===================================\n');

let totalBashTests = 0;
let totalNodeTests = 0;
let totalMissing = 0;
let totalExtra = 0;

const results = [];

testSuites.forEach(suite => {
    // Handle special cases
    let checkSuite = suite;
    if (suite === 'permissions') {
        checkSuite = 'auth'; // permissions is in auth folder
        const bashPath = path.join(__dirname, 'auth', `test-permissions.sh`);
        const nodePath = path.join(__dirname, 'auth', `test-permissions.js`);
        
        if (fs.existsSync(bashPath)) {
            const bashTests = extractBashTests(bashPath);
            const nodeTests = fs.existsSync(nodePath) ? extractNodeTests(nodePath) : [];
            
            const result = {
                suite: 'permissions',
                bashPath,
                nodePath,
                bashTests,
                nodeTests,
                comparison: compareTests(bashTests, nodeTests)
            };
            
            results.push(result);
            totalBashTests += bashTests.length;
            totalNodeTests += nodeTests.length;
            totalMissing += result.comparison.missing.length;
            totalExtra += result.comparison.extra.length;
        }
    } else if (suite !== 'permissions') {
        const result = checkTestSuite(suite);
        if (result) {
            results.push(result);
            totalBashTests += result.bashTests.length;
            totalNodeTests += result.nodeTests.length;
            totalMissing += result.comparison.missing.length;
            totalExtra += result.comparison.extra.length;
        }
    }
});

// Print detailed results
results.forEach(result => {
    console.log(`\n${result.suite.toUpperCase()} Test Suite`);
    console.log('-'.repeat(40));
    console.log(`Bash tests: ${result.bashTests.length}`);
    console.log(`Node tests: ${result.nodeTests.length}`);
    
    if (result.comparison.missing.length > 0) {
        console.log('\n  Missing in Node.js:');
        result.comparison.missing.forEach(m => {
            console.log(`    - ${m.bash} (expected: ${m.expectedNode})`);
        });
    }
    
    if (result.comparison.extra.length > 0) {
        console.log('\n  Extra in Node.js (not in bash):');
        result.comparison.extra.forEach(e => {
            console.log(`    + ${e}`);
        });
    }
    
    if (result.comparison.missing.length === 0 && result.comparison.extra.length === 0) {
        console.log('  ✓ All tests migrated successfully');
    }
});

// Print summary
console.log('\n' + '='.repeat(50));
console.log('SUMMARY');
console.log('='.repeat(50));
console.log(`Total bash tests: ${totalBashTests}`);
console.log(`Total Node.js tests: ${totalNodeTests}`);
console.log(`Missing migrations: ${totalMissing}`);
console.log(`Extra Node.js tests: ${totalExtra}`);

if (totalMissing === 0) {
    console.log('\n✓ All bash tests have been migrated to Node.js!');
} else {
    console.log(`\n⚠ ${totalMissing} tests still need to be migrated`);
}

// Export results for other scripts
if (process.argv.includes('--json')) {
    console.log('\n' + JSON.stringify(results, null, 2));
}

process.exit(totalMissing > 0 ? 1 : 0);
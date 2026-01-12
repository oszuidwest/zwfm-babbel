// Custom test sequencer to enforce test execution order
// Tests must run in dependency order (auth first, validation last)
const Sequencer = require('@jest/test-sequencer').default;

class CustomSequencer extends Sequencer {
  // Define execution order matching the original run-all.js
  static ORDER = [
    'auth/auth.test.js',
    'auth/permissions.test.js',
    'stations/stations.test.js',
    'voices/voices.test.js',
    'station-voices/station-voices.test.js',
    'stories/stories.test.js',
    'bulletins/bulletins.test.js',
    'automation/automation.test.js',
    'users/users.test.js',
    'validation/validation.test.js'
  ];

  sort(tests) {
    return tests.sort((a, b) => {
      const aIndex = CustomSequencer.ORDER.findIndex(p => a.path.includes(p));
      const bIndex = CustomSequencer.ORDER.findIndex(p => b.path.includes(p));

      // Unknown tests go to the end
      const aOrder = aIndex === -1 ? 999 : aIndex;
      const bOrder = bIndex === -1 ? 999 : bIndex;

      return aOrder - bOrder;
    });
  }
}

module.exports = CustomSequencer;

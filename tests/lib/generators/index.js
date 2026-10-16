const { generateQueryTests, generateTrashedTests } = require('./QueryTestGenerator');
const { generateCrudTests } = require('./CrudTestGenerator');
const { generateValidationTests } = require('./ValidationTestGenerator');

module.exports = {
  generateQueryTests,
  generateTrashedTests,
  generateCrudTests,
  generateValidationTests
};

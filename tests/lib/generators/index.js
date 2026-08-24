const { generateQueryTests } = require('./QueryTestGenerator');
const { generateCrudTests } = require('./CrudTestGenerator');
const { generateValidationTests } = require('./ValidationTestGenerator');

module.exports = {
  generateQueryTests,
  generateCrudTests,
  generateValidationTests
};

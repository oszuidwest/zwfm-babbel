/**
 * Resource Schemas - Centralized exports for all resource schemas.
 */

const stationsSchema = require('./stations.schema');
const voicesSchema = require('./voices.schema');
const usersSchema = require('./users.schema');
const storiesSchema = require('./stories.schema');
const stationVoicesSchema = require('./station-voices.schema');
const bulletinsSchema = require('./bulletins.schema');

module.exports = {
  stationsSchema,
  voicesSchema,
  usersSchema,
  storiesSchema,
  stationVoicesSchema,
  bulletinsSchema
};

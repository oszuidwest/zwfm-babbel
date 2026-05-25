// Shared MySQL helpers for integration tests and fixture loading.
const { execFileSync } = require('child_process');
const { parseSafeInteger } = require('./numeric');

const mysqlEscapeMap = {
  '\0': '\\0',
  '\b': '\\b',
  '\t': '\\t',
  '\n': '\\n',
  '\r': '\\r',
  '\x1a': '\\Z',
  '"': '\\"',
  "'": "\\'",
  '\\': '\\\\'
};

const mysqlEscapePattern = /[\0\b\t\n\r\x1a"'\\]/g;

function commandErrorMessage(error) {
  const parts = [];
  if (error?.message) {
    parts.push(error.message);
  }
  const stderr = error?.stderr?.toString().trim();
  if (stderr) {
    parts.push(`stderr: ${stderr}`);
  }
  const stdout = error?.stdout?.toString().trim();
  if (stdout) {
    parts.push(`stdout: ${stdout}`);
  }
  return parts.join('; ') || String(error);
}

function sqlString(value, label = 'value') {
  if (typeof value !== 'string') {
    throw new Error(`Invalid ${label}: expected a string`);
  }
  return `'${value.replace(mysqlEscapePattern, (char) => mysqlEscapeMap[char])}'`;
}

function sqlInteger(value, label = 'value') {
  return String(parseSafeInteger(value, label));
}

function mysqlConfigFromEnv(env = process.env) {
  return {
    user: env.MYSQL_USER || 'babbel',
    password: env.MYSQL_PASSWORD || 'babbel',
    database: env.MYSQL_DATABASE || 'babbel',
    host: env.MYSQL_HOST || 'localhost',
    container: env.MYSQL_CONTAINER || 'babbel-mysql'
  };
}

function isDockerContainerRunning(container, logger = console) {
  try {
    const containers = execFileSync('docker', ['ps', '--format', '{{.Names}}'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe']
    }).trim().split('\n').filter(Boolean);
    const running = containers.includes(container);
    if (!running) {
      logger.warn(`Docker container ${container} is not running; falling back to direct MySQL.`);
    }
    return running;
  } catch (error) {
    logger.warn(
      `Could not inspect Docker containers; falling back to direct MySQL. ${commandErrorMessage(error)}`
    );
    return false;
  }
}

function createMySQLExecutor(options = {}) {
  const config = {
    ...mysqlConfigFromEnv(options.env),
    ...(options.config || {})
  };
  const logger = options.logger || console;
  let cachedTarget = null;

  function resolveTarget() {
    if (cachedTarget) {
      return cachedTarget;
    }
    if (isDockerContainerRunning(config.container, logger)) {
      cachedTarget = {
        label: `Docker MySQL container ${config.container}`,
        bin: 'docker',
        args: ['exec', '-i', config.container, 'mysql', '-u', config.user, `-p${config.password}`, config.database]
      };
    } else {
      cachedTarget = {
        label: `direct MySQL at ${config.host}`,
        bin: 'mysql',
        args: ['-h', config.host, '-u', config.user, `-p${config.password}`, config.database]
      };
    }
    return cachedTarget;
  }

  return {
    describeTarget() {
      return resolveTarget().label;
    },

    execSQL(sql, options = {}) {
      const { silent = false, ...execOptions } = options;
      const target = resolveTarget();
      const mysqlFlags = silent ? ['-N', '-s'] : [];
      try {
        return execFileSync(target.bin, [...target.args, ...mysqlFlags, '-e', sql], {
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
          ...execOptions
        });
      } catch (error) {
        throw new Error(`MySQL command failed via ${target.label}: ${commandErrorMessage(error)}`);
      }
    },

    execSQLScript(input, execOptions = {}) {
      const target = resolveTarget();
      try {
        return execFileSync(target.bin, target.args, {
          input,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
          ...execOptions
        });
      } catch (error) {
        throw new Error(`MySQL script failed via ${target.label}: ${commandErrorMessage(error)}`);
      }
    }
  };
}

module.exports = {
  commandErrorMessage,
  createMySQLExecutor,
  isDockerContainerRunning,
  sqlInteger,
  sqlString
};

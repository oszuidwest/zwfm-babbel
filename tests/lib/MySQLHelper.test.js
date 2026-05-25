jest.mock('child_process', () => ({
  execFileSync: jest.fn()
}));

const { execFileSync } = require('child_process');
const {
  createMySQLExecutor,
  isDockerContainerRunning,
  sqlInteger,
  sqlString
} = require('./MySQLHelper');

describe('MySQLHelper', () => {
  beforeEach(() => {
    execFileSync.mockReset();
  });

  test('when escaping SQL strings, then MySQL metacharacters are quoted', () => {
    expect(sqlString("a'b\\c\n")).toBe("'a\\'b\\\\c\\n'");
    expect(sqlString('plain')).toBe("'plain'");
  });

  test('when SQL string input is not a string, then rejected', () => {
    expect(() => sqlString(null, 'filename')).toThrow(/filename/);
    expect(() => sqlString(undefined, 'filename')).toThrow(/filename/);
    expect(() => sqlString(new Date('2024-01-01T00:00:00Z'), 'created_at')).toThrow(/created_at/);
  });

  test('when SQL integer is unsafe, then rejected', () => {
    expect(sqlInteger('42')).toBe('42');
    expect(() => sqlInteger('42; DROP TABLE users', 'station ID')).toThrow(/station ID/);
    expect(() => sqlInteger(Number.MAX_SAFE_INTEGER + 1, 'station ID')).toThrow(/station ID/);
    expect(() => sqlInteger(true, 'station ID')).toThrow(/station ID/);
    expect(() => sqlInteger(1.5, 'station ID')).toThrow(/station ID/);
  });

  test('when Docker inspection fails, then fallback is visible', () => {
    const logger = { warn: jest.fn() };
    const error = new Error('docker ps failed');
    error.stderr = Buffer.from('Cannot connect to Docker daemon');
    execFileSync.mockImplementation(() => {
      throw error;
    });

    expect(isDockerContainerRunning('babbel-mysql', logger)).toBe(false);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('Cannot connect to Docker daemon'));
  });

  test('when Docker container is absent, then fallback is visible', () => {
    const logger = { warn: jest.fn() };
    execFileSync.mockReturnValue('other-container\n');

    expect(isDockerContainerRunning('babbel-mysql', logger)).toBe(false);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('babbel-mysql'));
  });

  test('when Docker container is unavailable, then executor uses direct MySQL with a warning', () => {
    const logger = { warn: jest.fn() };
    const error = new Error('docker ps failed');
    error.stderr = Buffer.from('daemon unavailable');
    execFileSync.mockImplementation((bin, args) => {
      if (bin === 'docker' && args[0] === 'ps') {
        throw error;
      }
      return 'ok';
    });

    const mysql = createMySQLExecutor({
      logger,
      env: {
        MYSQL_HOST: 'db.local',
        MYSQL_USER: 'tester',
        MYSQL_PASSWORD: 'secret',
        MYSQL_DATABASE: 'babbel_test',
        MYSQL_CONTAINER: 'babbel-mysql'
      }
    });

    expect(mysql.execSQL('SELECT 1')).toBe('ok');
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('daemon unavailable'));
    expect(execFileSync).toHaveBeenLastCalledWith(
      'mysql',
      ['-h', 'db.local', '-u', 'tester', '-psecret', 'babbel_test', '-e', 'SELECT 1'],
      expect.objectContaining({ encoding: 'utf-8' })
    );
  });

  test('when Docker container is running, then executor uses docker exec argv', () => {
    execFileSync.mockImplementation((bin, args) => {
      if (bin === 'docker' && args[0] === 'ps') {
        return 'babbel-mysql\n';
      }
      return 'ok';
    });

    const mysql = createMySQLExecutor();

    expect(mysql.execSQL('SELECT 1')).toBe('ok');
    expect(execFileSync).toHaveBeenLastCalledWith(
      'docker',
      ['exec', '-i', 'babbel-mysql', 'mysql', '-u', 'babbel', '-pbabbel', 'babbel', '-e', 'SELECT 1'],
      expect.objectContaining({ encoding: 'utf-8' })
    );
  });

  test('when execSQL fails, then stderr is included', () => {
    execFileSync.mockImplementation((bin, args) => {
      if (bin === 'docker' && args[0] === 'ps') {
        return 'babbel-mysql\n';
      }
      const error = new Error('Command failed');
      error.stderr = Buffer.from('ERROR 1049 (42000): Unknown database');
      throw error;
    });

    const mysql = createMySQLExecutor();

    expect(() => mysql.execSQL('SELECT 1')).toThrow(/Unknown database/);
  });

  test('when execSQLScript runs, then input is piped to mysql', () => {
    execFileSync.mockImplementation((bin, args) => {
      if (bin === 'docker' && args[0] === 'ps') {
        return 'babbel-mysql\n';
      }
      return 'loaded';
    });

    const mysql = createMySQLExecutor();

    expect(mysql.execSQLScript('INSERT INTO x VALUES (1)')).toBe('loaded');
    expect(execFileSync).toHaveBeenLastCalledWith(
      'docker',
      ['exec', '-i', 'babbel-mysql', 'mysql', '-u', 'babbel', '-pbabbel', 'babbel'],
      expect.objectContaining({
        input: 'INSERT INTO x VALUES (1)',
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe']
      })
    );
  });

  test('when execSQLScript fails, then stderr is included', () => {
    execFileSync.mockImplementation((bin, args) => {
      if (bin === 'docker' && args[0] === 'ps') {
        return 'babbel-mysql\n';
      }
      const error = new Error('Command failed');
      error.stderr = Buffer.from('ERROR 1064 (42000): syntax error');
      throw error;
    });

    const mysql = createMySQLExecutor();

    expect(() => mysql.execSQLScript('bad sql')).toThrow(/syntax error/);
  });
});

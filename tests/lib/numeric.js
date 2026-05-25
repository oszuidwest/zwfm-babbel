// Numeric value guards shared by test helpers.

const decimalNumberPattern = /^-?(?:\d+|\d*\.\d+)$/;

function invalidNumber(label, expected) {
  return new Error(`Invalid ${label}: expected ${expected}`);
}

function parseSafeInteger(value, label = 'value') {
  if (value === null || value === undefined || typeof value === 'boolean' || Array.isArray(value)) {
    throw invalidNumber(label, 'a safe integer');
  }

  let parsed;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!/^-?\d+$/.test(trimmed)) {
      throw invalidNumber(label, 'a safe integer');
    }
    parsed = Number(trimmed);
  } else {
    parsed = value;
  }

  if (!Number.isSafeInteger(parsed)) {
    throw invalidNumber(label, 'a safe integer');
  }

  return parsed;
}

function parseFiniteNumber(value, label = 'value') {
  let parsed;
  if (typeof value === 'number') {
    parsed = value;
  } else if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!decimalNumberPattern.test(trimmed)) {
      throw invalidNumber(label, 'a finite number');
    }
    parsed = Number(trimmed);
  } else {
    throw invalidNumber(label, 'a finite number');
  }

  if (!Number.isFinite(parsed)) {
    throw invalidNumber(label, 'a finite number');
  }

  return parsed;
}

module.exports = {
  parseFiniteNumber,
  parseSafeInteger
};

// Minimal strict validators for the engine's JSON contracts. Types are inferred
// from the validators, so each wire shape is written down exactly once and the
// same definition is enforced at runtime.
//
// Objects are closed: a missing required key or an unexpected key is an error.
// The engine bumps schema_version whenever it adds an always-present field, so
// an unknown field means a schema this adapter has not been reviewed against.

export class SchemaError extends Error {
  constructor(
    readonly path: string,
    readonly problem: string,
  ) {
    super(`${path}: ${problem}`);
  }
}

export type Validator<T> = (value: unknown, path: string) => T;
export type Infer<V> = V extends Validator<infer T> ? T : never;

function describe(value: unknown) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return typeof value === "string" ? JSON.stringify(value).slice(0, 60) : typeof value;
}

export const string: Validator<string> = (value, path) => {
  if (typeof value !== "string") throw new SchemaError(path, `expected a string, got ${describe(value)}`);
  return value;
};

export const integer: Validator<number> = (value, path) => {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new SchemaError(path, `expected an integer, got ${describe(value)}`);
  }
  return value;
};

export function literal<const T extends string | number>(expected: T): Validator<T> {
  return (value, path) => {
    if (value !== expected) {
      throw new SchemaError(path, `expected ${JSON.stringify(expected)}, got ${describe(value)}`);
    }
    return expected;
  };
}

export function oneOf<const T extends readonly string[]>(values: T): Validator<T[number]> {
  return (value, path) => {
    if (typeof value !== "string" || !values.includes(value)) {
      throw new SchemaError(path, `expected one of ${values.join(" | ")}, got ${describe(value)}`);
    }
    return value as T[number];
  };
}

export function nullable<T>(inner: Validator<T>): Validator<T | null> {
  return (value, path) => (value === null ? null : inner(value, path));
}

export function array<T>(inner: Validator<T>): Validator<T[]> {
  return (value, path) => {
    if (!Array.isArray(value)) throw new SchemaError(path, `expected an array, got ${describe(value)}`);
    return value.map((item, index) => inner(item, `${path}[${index}]`));
  };
}

type Shape = Record<string, Validator<unknown>>;
type Required<S extends Shape> = { [K in keyof S]: Infer<S[K]> };
type Optional<S extends Shape> = { [K in keyof S]?: Infer<S[K]> };
type Flatten<T> = { [K in keyof T]: T[K] };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A closed object: every required key present, optional keys allowed, nothing else. */
export function object<S extends Shape, O extends Shape = Record<never, never>>(
  required: S,
  optional?: O,
): Validator<Flatten<Required<S> & Optional<O>>> {
  return (value, path) => {
    if (!isRecord(value)) throw new SchemaError(path, `expected an object, got ${describe(value)}`);
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      if (!Object.hasOwn(required, key) && !(optional && Object.hasOwn(optional, key))) {
        throw new SchemaError(`${path}.${key}`, "unexpected field");
      }
    }
    for (const [key, validate] of Object.entries(required)) {
      if (!Object.hasOwn(value, key)) throw new SchemaError(`${path}.${key}`, "missing field");
      out[key] = validate(value[key], `${path}.${key}`);
    }
    for (const [key, validate] of Object.entries(optional ?? {})) {
      if (Object.hasOwn(value, key)) out[key] = validate(value[key], `${path}.${key}`);
    }
    return out as Flatten<Required<S> & Optional<O>>;
  };
}

/** Adds a cross-field check; `check` returns a problem description or null. */
export function refine<T>(inner: Validator<T>, check: (value: T) => string | null): Validator<T> {
  return (value, path) => {
    const parsed = inner(value, path);
    const problem = check(parsed);
    if (problem) throw new SchemaError(path, problem);
    return parsed;
  };
}

/** Parses JSON text and validates it; throws SchemaError on any mismatch. */
export function parseJson<T>(text: string, validate: Validator<T>, root = "$"): T {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new SchemaError(root, `not valid JSON (${(error as Error).message})`);
  }
  return validate(value, root);
}

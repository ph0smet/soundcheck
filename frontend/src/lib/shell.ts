// POSIX shell quoting for the commands Soundcheck shows people to copy and run.
// Nothing here is ever executed by the server (the engine is spawned without a
// shell); the point is that a pasted command runs exactly the arguments shown.

// Characters no POSIX shell treats specially, provided the word does not start
// with `=` (zsh expands `=cmd`) or `~`. Everything else is single-quoted, which
// disables globbing, expansion, `;`, `|`, `&` and redirection.
const SAFE = /^[\w./:@%+,-][\w./:@%+,=-]*$/;

export function shellQuote(arg: string): string {
  if (SAFE.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

export function shellCommand(args: string[]): string {
  return args.map(shellQuote).join(" ");
}

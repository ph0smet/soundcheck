/** Empty solver strings are concrete values, not universal-method metadata. */
export function witnessMethod(action: string): string {
  return action === "" ? "(empty method)" : action;
}

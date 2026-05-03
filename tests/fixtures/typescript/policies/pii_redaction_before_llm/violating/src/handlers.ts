import * as anthropic from 'anthropic';

export function summarizeUser(userId: string): string {
  const user = loadUser(userId);
  return anthropic.messages.create({ model: 'claude', input: user });
}

export function loadUser(userId: string): { id: string; email: string } {
  return { id: userId, email: 'x@example.com' };
}

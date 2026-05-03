import { redact } from './redactor';
import * as anthropic from 'anthropic';

export function summarizeUser(userId: string): string {
  const user = loadUser(userId);
  const safe = redact(user);
  return anthropic.messages.create({ model: 'claude', input: safe });
}

export function loadUser(userId: string): { id: string; email: string } {
  return { id: userId, email: 'x@example.com' };
}

import * as anthropic from 'anthropic';

export const summarizeUser = (userId: string): string => {
  const user = loadUser(userId);
  return anthropic.messages.create({ model: 'claude', input: user });
};

export const loadUser = (userId: string) => ({ id: userId, email: 'x@example.com' });

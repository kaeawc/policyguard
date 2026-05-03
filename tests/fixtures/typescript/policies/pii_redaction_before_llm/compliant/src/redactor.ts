export function redact(user: { id: string; email: string }): { id: string; email: string } {
  return { id: user.id, email: '***' };
}

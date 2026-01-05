export const resolveBaseUrl = (envValue: string | undefined, fallback: string) => {
  const raw = envValue?.trim();
  const base = raw && raw.length > 0 ? raw : fallback;
  if (!base) {
    return '';
  }

  const trimmed = base.replace(/\/$/, '');
  if (trimmed.startsWith('/')) {
    return trimmed;
  }

  const hasScheme = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed);
  const candidate = hasScheme ? trimmed : `http://${trimmed}`;

  try {
    const parsed = new URL(candidate);
    if (typeof window !== 'undefined') {
      const currentHost = window.location.hostname;
      const isLocalHost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
      if (isLocalHost && currentHost && currentHost !== parsed.hostname) {
        parsed.hostname = currentHost;
      }
    }
    const path = parsed.pathname === '/' ? '' : parsed.pathname;
    const resolved = `${parsed.protocol}//${parsed.host}${path}`;
    return resolved.replace(/\/$/, '');
  } catch {
    return trimmed;
  }
};

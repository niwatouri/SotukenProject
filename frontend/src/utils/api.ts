import { resolveBaseUrl } from './url';

export const API_BASE_URL = resolveBaseUrl(import.meta.env.VITE_API_URL, '/api');

// AegisVault — API response types

export interface ApiSuccess<T = unknown> {
  success: true;
  data: T;
}

export interface ApiError {
  success: false;
  error: string;
  code?: string;
  details?: unknown;
}

export type ApiResponse<T = unknown> = ApiSuccess<T> | ApiError;

// Helper to create typed responses
export function ok<T>(data: T): ApiSuccess<T> {
  return { success: true, data };
}

export function err(error: string, code?: string, details?: unknown): ApiError {
  return { success: false, error, code, details };
}

// Pagination
export interface PaginationMeta {
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
}

export interface PaginatedResponse<T> {
  items: T[];
  meta: PaginationMeta;
}

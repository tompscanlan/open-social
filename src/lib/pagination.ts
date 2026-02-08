export interface PaginationParams {
  cursor?: string;
  limit: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  cursor?: string;
  total?: number;
}

export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;

export function parsePagination(query: { cursor?: string; limit?: string | number }): PaginationParams {
  let limit = typeof query.limit === 'string' ? parseInt(query.limit, 10) : (query.limit ?? DEFAULT_PAGE_SIZE);
  if (isNaN(limit) || limit < 1) limit = DEFAULT_PAGE_SIZE;
  if (limit > MAX_PAGE_SIZE) limit = MAX_PAGE_SIZE;

  return {
    cursor: query.cursor || undefined,
    limit,
  };
}

export function encodeCursor(offset: number): string {
  return Buffer.from(String(offset)).toString('base64');
}

export function decodeCursor(cursor: string): number {
  try {
    const decoded = Buffer.from(cursor, 'base64').toString('utf-8');
    const num = parseInt(decoded, 10);
    return isNaN(num) ? 0 : num;
  } catch {
    return 0;
  }
}

export function paginateArray<T>(items: T[], params: PaginationParams): PaginatedResponse<T> {
  const offset = params.cursor ? decodeCursor(params.cursor) : 0;
  const page = items.slice(offset, offset + params.limit);
  const nextOffset = offset + params.limit;
  
  return {
    data: page,
    cursor: nextOffset < items.length ? encodeCursor(nextOffset) : undefined,
    total: items.length,
  };
}

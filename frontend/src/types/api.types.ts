/** API Types */
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: number;
    message: string;
  };
}

export interface PaginatedResponse<T = any> {
  success: boolean;
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: T[];
}

export interface ApiError {
  response?: {
    status: number;
    data: {
      error: { code: number; message: string };
    };
  };
  message: string;
}

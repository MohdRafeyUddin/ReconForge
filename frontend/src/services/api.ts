export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";
export const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL || "ws://127.0.0.1:8000/api/v1";
export const SCREENSHOT_BASE_URL = API_BASE_URL.replace("/api/v1", "");

export interface ApiRequestOptions extends RequestInit {
  token?: string;
}

export const apiCall = async (endpoint: string, options: ApiRequestOptions = {}) => {
  const headers = new Headers(options.headers || {});
  if (!(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const config: RequestInit = {
    ...options,
    headers,
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Request failed");
  }

  // Handle HTML/binary response (e.g. HTML report export)
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("text/html")) {
    return response.text();
  }

  return response.json();
};

export const getWebSocketUrl = (endpoint: string): string => {
  return `${WS_BASE_URL}${endpoint}`;
};

export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:9000").replace(/\/$/, "");
export const WS_URL = API_URL.replace(/^http/, "ws");

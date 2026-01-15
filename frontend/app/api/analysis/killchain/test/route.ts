const BASE_URL = process.env.BACKEND_BASE_URL;

export async function POST(request: Request) {
  console.log("[TEST] Next.js API route /api/analysis/killchain/test called");
  console.log("[TEST] BASE_URL:", BASE_URL);
  
  if (!BASE_URL) {
    console.error("[TEST] BACKEND_BASE_URL is not configured");
    return Response.json(
      { status: "error", error: { code: "CONFIG", message: "BACKEND_BASE_URL is not configured." } },
      { status: 500 }
    );
  }

  const baseUrl = BASE_URL.endsWith("/") ? BASE_URL : `${BASE_URL}/`;
  const url = new URL("api/v1/analysis/killchain/test", baseUrl);
  console.log("[TEST] Forwarding to backend URL:", url.toString());

  const response = await fetch(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    cache: "no-store",
  });

  console.log("[TEST] Backend response status:", response.status);
  
  if (!response.ok) {
    const text = await response.text();
    console.error("[TEST] Backend returned error:", text);
    return new Response(text, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "text/plain",
      },
    });
  }

  const data = await response.json();
  console.log("[TEST] Backend response data:", data);
  return Response.json(data, { status: response.status });
}

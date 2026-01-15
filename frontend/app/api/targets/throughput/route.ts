const BASE_URL = process.env.BACKEND_BASE_URL;

export async function GET() {
  if (!BASE_URL) {
    return Response.json(
      { ok: false, error: "BACKEND_BASE_URL is not configured." },
      { status: 500 }
    );
  }

  const baseUrl = BASE_URL.endsWith("/") ? BASE_URL : `${BASE_URL}/`;
  const url = new URL("api/v1/targets/throughput", baseUrl);
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    const text = await response.text();
    return new Response(text, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "text/plain",
      },
    });
  }

  const data = await response.json();
  return Response.json(data, { status: response.status });
}

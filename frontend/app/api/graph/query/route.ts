const BASE_URL = process.env.BACKEND_BASE_URL;

export async function POST(request: Request) {
  if (!BASE_URL) {
    return Response.json(
      { ok: false, error: "BACKEND_BASE_URL is not configured." },
      { status: 500 }
    );
  }

  const baseUrl = BASE_URL.endsWith("/") ? BASE_URL : `${BASE_URL}/`;
  const url = new URL("api/v1/graph/query", baseUrl);

  let payload: unknown = null;
  try {
    payload = await request.json();
  } catch {
    payload = null;
  }

  const body =
    payload && typeof payload === "object"
      ? payload
      : { action: "alarm_edges" };

  const response = await fetch(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
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

const BASE_URL = process.env.BACKEND_BASE_URL;

export async function POST(request: Request) {
  if (!BASE_URL) {
    return Response.json(
      { status: "error", error: { code: "CONFIG", message: "BACKEND_BASE_URL is not configured." } },
      { status: 500 }
    );
  }

  const baseUrl = BASE_URL.endsWith("/") ? BASE_URL : `${BASE_URL}/`;
  const url = new URL("api/v1/analysis/tasks", baseUrl);

  let payload: unknown = null;
  try {
    payload = await request.json();
  } catch {
    payload = null;
  }

  const response = await fetch(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify(payload ?? {}),
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

export async function GET(request: Request) {
  if (!BASE_URL) {
    return Response.json(
      { ok: false, error: "BACKEND_BASE_URL is not configured." },
      { status: 500 }
    );
  }

  const baseUrl = BASE_URL.endsWith("/") ? BASE_URL : `${BASE_URL}/`;
  const url = new URL("api/v1/analysis/tasks", baseUrl);
  const requestUrl = new URL(request.url);
  requestUrl.searchParams.forEach((value, key) => {
    url.searchParams.append(key, value);
  });

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

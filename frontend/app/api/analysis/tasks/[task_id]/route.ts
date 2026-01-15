const BASE_URL = process.env.BACKEND_BASE_URL;

type RouteContext = {
  params: Promise<{ task_id: string }>;
};

export async function GET(request: Request, context: RouteContext) {
  if (!BASE_URL) {
    return Response.json(
      {
        status: "error",
        error: { code: "CONFIG", message: "BACKEND_BASE_URL is not configured." },
      },
      { status: 500 }
    );
  }

  const { task_id: taskId } = await context.params;
  if (!taskId) {
    return Response.json(
      { status: "error", error: { code: "BAD_REQUEST", message: "task_id is required" } },
      { status: 400 }
    );
  }

  const baseUrl = BASE_URL.endsWith("/") ? BASE_URL : `${BASE_URL}/`;
  const url = new URL(`api/v1/analysis/tasks/${encodeURIComponent(taskId)}`, baseUrl);

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


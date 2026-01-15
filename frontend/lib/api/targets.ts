export type TargetsResponse =
  | {
      status: "ok";
      targets: string[];
      server_time?: string;
    }
  | {
      status: "error";
      error: { code: string; message: string };
      server_time?: string;
    };

export async function fetchTargets(): Promise<TargetsResponse> {
  const response = await fetch("/api/v1/targets");
  if (!response.ok) {
    throw new Error("Failed to fetch targets");
  }
  return response.json();
}

export async function getTargetsLen(): Promise<number> {
  const data = await fetchTargets();
  if (data.status !== "ok") {
    throw new Error(data.error.message);
  }
  return data.targets.length;
}

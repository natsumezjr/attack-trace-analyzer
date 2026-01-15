export type TargetsResponse = {
  ok: boolean;
  targets: string[];
  server_time: string;
};

export async function fetchTargets(): Promise<TargetsResponse> {
  const response = await fetch("/api/targets");
  if (!response.ok) {
    throw new Error("Failed to fetch targets");
  }
  return response.json();
}

export async function getTargetsLen(): Promise<number> {
  const data = await fetchTargets();
  return data.targets.length;
}

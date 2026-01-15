export type ThroughputResponse =
  | {
      status: "ok";
      throughput_bytes: number;
      last_poll_time: string | null;
      server_time?: string;
    }
  | {
      status: "error";
      error: { code: string; message: string };
      server_time?: string;
    };

export async function fetchThroughput(): Promise<ThroughputResponse> {
  const response = await fetch("/api/v1/targets/throughput");
  if (!response.ok) {
    throw new Error("Failed to fetch throughput");
  }
  return response.json();
}

export async function getThroughputKb(): Promise<{
  kb: number;
  lastPollTime: string;
  serverTime: string;
}> {
  const data = await fetchThroughput();
  if (data.status !== "ok") {
    throw new Error(data.error.message);
  }
  return {
    kb: data.throughput_bytes / 1024,
    lastPollTime: data.last_poll_time ?? "",
    serverTime: data.server_time ?? "",
  };
}

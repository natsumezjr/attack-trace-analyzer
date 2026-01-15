export type ThroughputResponse = {
  ok: boolean;
  throughput_bytes: number;
  last_poll_time: string;
  server_time: string;
};

export async function fetchThroughput(): Promise<ThroughputResponse> {
  const response = await fetch("/api/targets/throughput");
  if (!response.ok) {
    throw new Error("Failed to fetch throughput");
  }
  return response.json();
}

export async function getThroughputKb(): Promise<{
  kb: number;
  serverTime: string;
}> {
  const data = await fetchThroughput();
  return {
    kb: data.throughput_bytes / 1024,
    serverTime: data.server_time,
  };
}

export type FindingsStage = "raw" | "canonical";

export type FindingsSearchRequest = {
  stage?: FindingsStage;
  start_ts?: string | null;
  end_ts?: string | null;
  host_id?: string | null;
  tactic_ids?: string[] | null;
  technique_ids?: string[] | null;
  rule_ids?: string[] | null;
  providers?: string[] | null;
  min_severity?: number | null;
  query?: Record<string, unknown> | null;
  size?: number;
  offset?: number;
  sort_order?: "asc" | "desc";
};

export type FindingsSearchResponse =
  | {
      status: "ok";
      total: number;
      items: Record<string, unknown>[];
      server_time?: string;
    }
  | {
      status: "error";
      error: { code: string; message: string };
      server_time?: string;
    };

export async function fetchFindingsSearch(
  payload: FindingsSearchRequest
): Promise<FindingsSearchResponse> {
  const response = await fetch("/api/v1/findings/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    try {
      const data = (await response.json()) as FindingsSearchResponse;
      return data;
    } catch {
      const text = await response.text();
      return {
        status: "error",
        error: { code: "HTTP_ERROR", message: text || "Failed to fetch findings" },
      };
    }
  }

  return response.json();
}

export async function fetchFindingsTotal(
  payload: Omit<FindingsSearchRequest, "size" | "offset">
): Promise<number> {
  const data = await fetchFindingsSearch({
    ...payload,
    // Minimize payload; we only need `total`.
    size: 1,
    offset: 0,
    sort_order: "desc",
  });

  if (data.status !== "ok") {
    throw new Error(data.error.message);
  }

  return data.total;
}

type OpenSearchQuery = Record<string, unknown>;

function buildTacticQuery(args: {
  tacticIds?: string[];
  tacticNames?: string[];
}): OpenSearchQuery {
  const should: OpenSearchQuery[] = [];

  if (Array.isArray(args.tacticIds) && args.tacticIds.length > 0) {
    should.push({ terms: { "threat.tactic.id": args.tacticIds } });
  }
  if (Array.isArray(args.tacticNames) && args.tacticNames.length > 0) {
    should.push({ terms: { "threat.tactic.name": args.tacticNames } });
  }

  if (should.length === 0) {
    return { match_none: {} };
  }

  if (should.length === 1) {
    return should[0]!;
  }

  return { bool: { should, minimum_should_match: 1 } };
}

export type AttackOverviewSegment = {
  label: string;
  value: number;
  color: string;
};

export type AttackOverview = {
  total: number;
  segments: AttackOverviewSegment[];
};

export async function fetchAttackOverview(): Promise<AttackOverview> {
  const stage: FindingsStage = "canonical";

  // Category definition (disjoint, priority-ordered):
  // 1) 横向移动 -> 2) 权限提升 -> 3) 数据外传 -> 4) 恶意登录 -> 5) 其他事件(剩余)
  const lateralQuery = buildTacticQuery({
    tacticIds: ["TA0008"],
    tacticNames: ["Lateral Movement"],
  });
  const privilegeBaseQuery = buildTacticQuery({
    tacticIds: ["TA0004"],
    tacticNames: ["Privilege Escalation"],
  });
  const exfilBaseQuery = buildTacticQuery({
    tacticIds: ["TA0010"],
    tacticNames: ["Exfiltration"],
  });
  const loginBaseQuery = buildTacticQuery({
    // "恶意登录" 没有严格的 ATT&CK tactic，对演示场景常用 Initial Access / Credential Access 近似表达。
    tacticIds: ["TA0006", "TA0001"],
    tacticNames: ["Credential Access", "Initial Access"],
  });

  const privilegeQuery: OpenSearchQuery = {
    bool: { must: [privilegeBaseQuery], must_not: [lateralQuery] },
  };
  const exfilQuery: OpenSearchQuery = {
    bool: {
      must: [exfilBaseQuery],
      must_not: [lateralQuery, privilegeBaseQuery],
    },
  };
  const loginQuery: OpenSearchQuery = {
    bool: {
      must: [loginBaseQuery],
      must_not: [lateralQuery, privilegeBaseQuery, exfilBaseQuery],
    },
  };

  const [total, lateral, privilege, exfil, login] = await Promise.all([
    fetchFindingsTotal({ stage }),
    fetchFindingsTotal({ stage, query: lateralQuery }),
    fetchFindingsTotal({ stage, query: privilegeQuery }),
    fetchFindingsTotal({ stage, query: exfilQuery }),
    fetchFindingsTotal({ stage, query: loginQuery }),
  ]);

  const other = Math.max(0, total - lateral - privilege - exfil - login);

  const segments: AttackOverviewSegment[] = [
    { label: "恶意登录", value: login, color: "var(--chart-1)" },
    { label: "权限提升", value: privilege, color: "var(--chart-2)" },
    { label: "横向移动", value: lateral, color: "var(--chart-3)" },
    { label: "数据外传", value: exfil, color: "var(--chart-4)" },
    { label: "其他事件", value: other, color: "var(--chart-5)" },
  ];

  return { total, segments };
}


interface Connection {
  instanceUrl: string;
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  buildName?: string;
}

let current: Connection | null = null;

function normalizeInstanceUrl(input: string): string {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  return url.replace(/\/+$/, "");
}

export interface ConnectResult {
  ok: boolean;
  instanceUrl?: string;
  expiresAt?: string;
  buildName?: string;
  error?: string;
}

export async function connectInstance(
  instanceUrlInput: string,
  clientId: string,
  clientSecret: string,
): Promise<ConnectResult> {
  const instanceUrl = normalizeInstanceUrl(instanceUrlInput);

  let tokenRes: Response;
  try {
    tokenRes = await fetch(`${instanceUrl}/oauth_token.do`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
  } catch (err) {
    return { ok: false, error: `Could not reach ${instanceUrl}: ${err instanceof Error ? err.message : String(err)}` };
  }

  if (!tokenRes.ok) {
    const body = await tokenRes.text().catch(() => "");
    return {
      ok: false,
      error: `OAuth token request failed (${tokenRes.status} ${tokenRes.statusText}): ${truncate(body)}`,
    };
  }

  let tokenBody: { access_token?: string; token_type?: string; expires_in?: number };
  try {
    tokenBody = await tokenRes.json();
  } catch {
    return { ok: false, error: "OAuth token response was not valid JSON." };
  }

  if (!tokenBody.access_token) {
    return { ok: false, error: "OAuth token response did not include an access_token." };
  }

  const expiresAt = Date.now() + (tokenBody.expires_in ?? 1800) * 1000;
  current = {
    instanceUrl,
    accessToken: tokenBody.access_token,
    tokenType: tokenBody.token_type ?? "Bearer",
    expiresAt,
  };

  const verify = await verifyConnection();
  if (!verify.ok) {
    current = null;
    return verify;
  }

  current.buildName = verify.buildName;
  return {
    ok: true,
    instanceUrl,
    expiresAt: new Date(expiresAt).toISOString(),
    buildName: verify.buildName,
  };
}

async function verifyConnection(): Promise<ConnectResult> {
  if (!current) return { ok: false, error: "Not connected." };

  let res: Response;
  try {
    res = await fetch(
      `${current.instanceUrl}/api/now/table/sys_properties?sysparm_query=name=glide.buildname&sysparm_limit=1&sysparm_fields=value`,
      { headers: { Authorization: `${current.tokenType} ${current.accessToken}`, Accept: "application/json" } },
    );
  } catch (err) {
    return { ok: false, error: `Connected but verification request failed: ${err instanceof Error ? err.message : String(err)}` };
  }

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    return { ok: false, error: `Token was issued but a test API call failed (${res.status} ${res.statusText}): ${truncate(body)}` };
  }

  let json: { result?: { value?: string }[] };
  try {
    json = await res.json();
  } catch {
    return { ok: false, error: "Test API call returned a non-JSON response." };
  }

  return { ok: true, buildName: json.result?.[0]?.value };
}

export function getConnectionStatus(): { connected: boolean; instanceUrl?: string; buildName?: string; expiresAt?: string; expired?: boolean } {
  if (!current) return { connected: false };
  return {
    connected: true,
    instanceUrl: current.instanceUrl,
    buildName: current.buildName,
    expiresAt: new Date(current.expiresAt).toISOString(),
    expired: Date.now() >= current.expiresAt,
  };
}

export function disconnectInstance(): void {
  current = null;
}

function truncate(s: string, max = 300): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

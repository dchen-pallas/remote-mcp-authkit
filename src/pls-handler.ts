import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";

// Types
interface CallbackResponse {
	access_token: string;
	refresh_token: string;
	user: { id: string };
	organization_id: string;
	oauth_req_info: AuthRequest & {
		codeChallenge?: string;
		codeChallengeMethod?: string;
	};
}

const app = new Hono<{
	Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers };
}>();

// OAuth Discovery Endpoints
app.get("/.well-known/oauth-protected-resource", (c) => {
	const baseUrl = new URL(c.req.url).origin;
	return c.json({
		resource: baseUrl,
		authorization_servers: [baseUrl],
		scopes_supported: ["mcp:read", "mcp:write", "mcp:sse"],
		bearer_methods_supported: ["header"],
		resource_documentation: `${baseUrl}/docs`
	});
});

app.get("/.well-known/oauth-authorization-server/sse", (c) => {
	const baseUrl = new URL(c.req.url).origin;
	return c.json({
		issuer: baseUrl,
		sse_endpoint: `${baseUrl}/sse`,
		token_endpoint: `${baseUrl}/token`,
		scopes_supported: ["mcp:sse", "mcp:read", "mcp:write"],
		code_challenge_methods_supported: ["S256", "plain"]
	});
});

const createCorsHeaders = () => ({
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type, Authorization"
});

app.options("/.well-known/oauth-protected-resource", (c) => {
	return new Response(null, {
		status: 204,
		headers: createCorsHeaders()
	});
});

app.options("/.well-known/oauth-authorization-server/sse", (c) => {
	return new Response(null, {
		status: 204,
		headers: createCorsHeaders()
	});
});

// Add this after the existing SSE well-known endpoint
app.get("/.well-known/oauth-authorization-server/mcp", (c) => {
	const baseUrl = new URL(c.req.url).origin;
	return c.json({
		issuer: baseUrl,
		mcp_endpoint: `${baseUrl}/mcp`,
		token_endpoint: `${baseUrl}/token`,
		scopes_supported: ["mcp:read", "mcp:write"],
		code_challenge_methods_supported: ["S256", "plain"],
		transport: "http"
	});
});

// Add this after the existing OPTIONS handlers
app.options("/.well-known/oauth-authorization-server/mcp", (c) => {
	return new Response(null, {
		status: 204,
		headers: createCorsHeaders()
	});
});

const extractPkceParams = (url: URL) => ({
	codeChallenge: url.searchParams.get("code_challenge"),
	codeChallengeMethod: url.searchParams.get("code_challenge_method")
});

const buildStateParam = (oauthReqInfo: AuthRequest, pkceParams: ReturnType<typeof extractPkceParams>) => 
	btoa(JSON.stringify({
		...oauthReqInfo,
		...pkceParams
	}));

app.get("/authorize", async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	if (!oauthReqInfo.clientId) {
		return c.text("Invalid request", 400);
	}

	console.info("OAuth request info:", oauthReqInfo);
	
	const url = new URL(c.req.url);
	const pkceParams = extractPkceParams(url);
	
	console.info("PKCE params:", pkceParams);

	const state = buildStateParam(oauthReqInfo, pkceParams);
	
	// Build URL to Python backend
	const backendUrl = new URL("/auth/sso/authorize", "http://localhost:8080");
	backendUrl.searchParams.set("state", state);
	
	if (pkceParams.codeChallenge && pkceParams.codeChallengeMethod) {
		console.info("Adding PKCE params to backend request");
	}

	console.info("Redirecting to Python backend:", backendUrl.toString());
	
	return Response.redirect(backendUrl.toString());
});

const validateCallbackParams = (code: string | null, state: string | null) => {
	if (!state) throw new Error("Missing state parameter");
	if (!code) throw new Error("Missing code parameter");
};

const parseOAuthState = (stateParam: string): AuthRequest & { codeChallenge?: string; codeChallengeMethod?: string } => {
	try {
		return JSON.parse(atob(stateParam));
	} catch {
		throw new Error("Invalid state parameter");
	}
};

const fetchAuthenticationResult = async (code: string, state: string): Promise<CallbackResponse> => {
	const backendUrl = new URL("/auth/sso/callback", "http://localhost:8080");
	backendUrl.searchParams.set("code", code);
	backendUrl.searchParams.set("state", state);

	const response = await fetch(backendUrl.toString());
	
	if (!response.ok) {
		throw new Error(`Backend authentication failed: ${response.status}`);
	}

	return response.json() as Promise<CallbackResponse>;
};

const extractScopeFromToken = (accessToken: string): string[] => {
	try {
		const payload = JSON.parse(atob(accessToken.split('.')[1]));
		return payload.permissions || [];
	} catch {
		console.warn("Could not decode access token for permissions");
		return [];
	}
};

app.get("/callback", async (c) => {
	console.info("Callback endpoint hit");
	
	const code = c.req.query("code");
	const state = c.req.query("state");
	
	try {
		validateCallbackParams(code, state);
		
		console.info("Fetching authentication result from Python backend");
		const authResult = await fetchAuthenticationResult(code!, state!);
		
		const oauthReqInfo = authResult.oauth_req_info;
		console.info("Decoded OAuth request info:", oauthReqInfo);
		
		if (!oauthReqInfo.clientId) {
			return c.text("Invalid state", 400);
		}

		const scope = authResult.permissions|| extractScopeFromToken(authResult.access_token); 

		const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
			request: oauthReqInfo,
			userId: authResult.user.id,
			metadata: {},
			scope,
			props: {
				accessToken: authResult.access_token,
				organizationId: authResult.organization_id,
				permissions: scope,
				refreshToken: authResult.refresh_token,
				user: authResult.user,
			}
		});

		console.info("Redirecting to:", redirectTo);
		return Response.redirect(redirectTo);
		
	} catch (error) {
		console.error("Callback processing error:", error);
		const message = error instanceof Error ? error.message : "Authentication failed";
		return c.text(message, 400);
	}
});

export { app as AuthkitHandler };

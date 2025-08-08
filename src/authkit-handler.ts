import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import * as jose from "jose";
import { type AccessToken, type AuthenticationResponse, WorkOS } from "@workos-inc/node";
import type { Props } from "./props";

const app = new Hono<{
	Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers };
	Variables: { workOS: WorkOS };
}>();

app.use(async (c, next) => {
	c.set("workOS", new WorkOS(c.env.WORKOS_CLIENT_SECRET));
	await next();
});

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

// CORS support for discovery endpoints
app.options("/.well-known/oauth-protected-resource", (c) => {
	return new Response(null, {
		status: 204,
		headers: {
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization"
		}
	});
});

app.options("/.well-known/oauth-authorization-server/sse", (c) => {
	return new Response(null, {
		status: 204,
		headers: {
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS", 
			"Access-Control-Allow-Headers": "Content-Type, Authorization"
		}
	});
});

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

app.options("/.well-known/oauth-authorization-server/mcp", (c) => {
	return new Response(null, {
		status: 204,
		headers: createCorsHeaders()
	});
});

app.get("/authorize", async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	if (!oauthReqInfo.clientId) {
		return c.text("Invalid request", 400);
	}

	console.info("OAuth request info:", oauthReqInfo);
	
	// Extract PKCE parameters from the request
	const url = new URL(c.req.url);
	const codeChallenge = url.searchParams.get("code_challenge");
	const codeChallengeMethod = url.searchParams.get("code_challenge_method");
	
	console.info("PKCE params:", { codeChallenge, codeChallengeMethod });

	// Build authorization URL parameters
	const authParams: any = {
		provider: "authkit",
		clientId: c.env.WORKOS_CLIENT_ID,
		redirectUri: new URL("/callback", c.req.url).href,
		state: btoa(JSON.stringify({
			...oauthReqInfo,
			codeChallenge,
			codeChallengeMethod
		})),
	};

	// Add PKCE parameters to WorkOS authorization if present
	if (codeChallenge && codeChallengeMethod) {
		authParams.codeChallenge = codeChallenge;
		authParams.codeChallengeMethod = codeChallengeMethod;
		console.info("Adding PKCE to WorkOS authorization");
	}

	const authUrl = c.get("workOS").userManagement.getAuthorizationUrl(authParams);
	console.info("Authorization URL:", authUrl);
	
	return Response.redirect(authUrl);
});

app.get("/callback", async (c) => {
	console.info("Callback endpoint hit");
	const workOS = c.get("workOS");
	const stateParam = c.req.query("state");
	
	if (!stateParam) {
		return c.text("Missing state parameter", 400);
	}

	const oauthReqInfo = JSON.parse(atob(stateParam)) as AuthRequest & {
		codeChallenge?: string;
		codeChallengeMethod?: string;
	};
	
	console.info("Decoded OAuth request info:", oauthReqInfo);
	
	if (!oauthReqInfo.clientId) {
		return c.text("Invalid state", 400);
	}

	const code = c.req.query("code");
	if (!code) {
		return c.text("Missing code", 400);
	}

	let response: AuthenticationResponse;
	try {
		// Build authentication parameters
		const authParams: any = {
			clientId: c.env.WORKOS_CLIENT_ID,
			code,
		};

		// Add code verifier if this was a PKCE flow
		// Note: The code_verifier should come from the OAuth provider's state
		// For now, we'll let WorkOS handle the PKCE validation since we passed
		// the challenge parameters during authorization
		
		response = await workOS.userManagement.authenticateWithCode(authParams);
		console.info("Authentication successful");
	} catch (error) {
		console.error("Authentication error:", error);
		return c.text("Invalid authorization code", 400);
	}

	const { accessToken, organizationId, refreshToken, user } = response;
	const { permissions = [] } = jose.decodeJwt<AccessToken>(accessToken);

	const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
		request: oauthReqInfo,
		userId: user.id,
		metadata: {},
		scope: permissions,
		props: {
			accessToken,
			organizationId,
			permissions,
			refreshToken,
			user,
		} satisfies Props,
	});

	console.info("Redirecting to:", redirectTo);
	return Response.redirect(redirectTo);
});

export const AuthkitHandler = app;

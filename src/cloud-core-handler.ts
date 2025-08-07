import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import type { Props } from "./props";

const app = new Hono<{
	Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers };
	Variables: {};
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
		scopes_supported: ["mcp:sse", "mcp:read", "mcp:write"]
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

app.get("/authorize", async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	if (!oauthReqInfo.clientId) {
		return c.text("Invalid request", 400);
	}

	// Forward to FastAPI OAuth authorize endpoint
	const fastApiUrl = "http://localhost:8080";
	const params = new URLSearchParams({
		client_id: oauthReqInfo.clientId,
		redirect_uri: new URL("/callback", c.req.url).href,
		response_type: oauthReqInfo.responseType || "code",
		scope: oauthReqInfo.scope || "",
		state: btoa(JSON.stringify(oauthReqInfo))
	});

	const redirectUrl = `${fastApiUrl}/auth/sso/authorize?${params.toString()}`;
    console.debug(redirectUrl)
	return Response.redirect(redirectUrl);
});

app.get("/callback", async (c) => {
	try {
		const code = c.req.query("code");
		const authData = c.req.query("auth_data");
		const error = c.req.query("error");
		
		if (error) {
			return c.text(`Authentication failed: ${error}`, 400);
		}

		if (!code || !authData) {
			return c.text("Missing required parameters", 400);
		}

		// Decode auth data from FastAPI
		const decodedAuthData = JSON.parse(atob(authData));
		const { access_token, refresh_token, user, permissions, organization_id } = decodedAuthData;

		// Get original OAuth request from state (if needed)
		// For simplicity, we'll reconstruct it or store it in a way that works with your flow
        
        console.info("am i doing stuf here")
		
		// Complete OAuth authorization
		const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
			request: {
				clientId: c.req.query("client_id") || "",
				redirectUri: c.req.query("redirect_uri") || "",
				responseType: "code",
				scope: permissions.join(" ")
			} as AuthRequest,
			userId: user.id,
			metadata: {},
			scope: permissions,
			props: {
				accessToken: access_token,
				organizationId: organization_id,
				permissions,
				refreshToken: refresh_token,
				user,
			} satisfies Props,
		});

		return Response.redirect(redirectTo);
	} catch (error) {
		console.error("Callback error:", error);
		return c.text("Callback processing failed", 500);
	}
});

// Proxy token endpoint to FastAPI
app.post("/token", async (c) => {
	const fastApiUrl =  "http://localhost:8080";
	
	// Forward the entire request to FastAPI
	const response = await fetch(`${fastApiUrl}/auth/oauth/token`, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			...Object.fromEntries(c.req.raw.headers.entries())
		},
		body: await c.req.raw.text()
	});

	// Return the FastAPI response
	return new Response(response.body, {
		status: response.status,
		headers: response.headers
	});
});

export const AuthkitHandler = app;

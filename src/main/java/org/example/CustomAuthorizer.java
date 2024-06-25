package org.example;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CustomAuthorizer implements RequestHandler<APIGatewayProxyRequestEvent, Map<String, Object>> {

    private static final String COGNITO_TOKEN_URL = "http://localhost:8080/realms/aws_api_gateway/protocol/openid-connect/token";
    private static final String CLIENT_ID = "3k50udfb4thaslrd5tgi91im6b";
    private static final String CLIENT_SECRET = "1eo0e404amgosdht99cdegs0rfd4orhlcbhqgbl42kq2jh6uuorp";

    @Override
    public Map<String, Object> handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        LambdaLogger lambdaLogger = context.getLogger();
        lambdaLogger.log("Body = " + event.getBody());
        event.getHeaders().entrySet()
                                 .forEach(e-> lambdaLogger.log("key = "+ e.getKey() + " , value = " + e.getValue()+ "\n") );
        Map<String, String> headers = event.getHeaders();
        String resource = headers.get("methodArn");
        Map<String, String> ctx = new HashMap<>();

        APIGatewayProxyRequestEvent.ProxyRequestContext proxyContext = event.getRequestContext();
        String arn = String.format("arn:aws:execute-api:%s:%s:%s/%s/%s/%s",
                                   System.getenv("AWS_REGION"),
                                   proxyContext.getAccountId(),
                                   proxyContext.getApiId(),
                                   proxyContext.getStage(),
                                   proxyContext.getHttpMethod(),
                                   "*");
        lambdaLogger.log("Arn..." + arn);
        String effect = "Deny";
        try {
            // Extract authorization header
            String authorizationHeader = event.getHeaders().get("Authorization");

            // Check if header is present and starts with "Basic"
            if (authorizationHeader == null || !authorizationHeader.startsWith("Basic ")) {
                lambdaLogger.log("Missing or invalid Authorization header");
            }

            // Decode Base64 encoded credentials
            String decodedCredentials = new String(Base64.getDecoder().decode(authorizationHeader.substring(6)));

            // Split credentials into username and password (client ID and secret)
            String[] credentials = decodedCredentials.split(":");
            if (credentials.length != 2) {
                lambdaLogger.log("Invalid Authorization header format");
            }

//            String providedClientId = credentials[0];
//            String providedClientSecret = credentials[1];
//
//            // Validate client credentials against configured ones
//            if (!providedClientId.equals(clientId) || !providedClientSecret.equals(clientSecret)) {
//                return new RequestContext("Unauthorized", "Invalid client credentials");
//            }

            String accessToken = getAccessToken(credentials[0], credentials[1]);
            lambdaLogger.log("access token..." + accessToken);
            if (StringUtils.isNotBlank(accessToken)){
                effect = "Allow";
                lambdaLogger.log("Success, effect..." + effect);
                ctx.put("message", "Success");
            }

        } catch (Exception e) {
            ctx.put("message", e.getMessage());
            lambdaLogger.log("Deny, Exception..." + e.getMessage());
        }
        lambdaLogger.log("principalId = user, effect = " + effect + " , resource = " + arn);

        Map<String, Object> stringObjectMap = generatePolicy("user", effect, arn);
        lambdaLogger.log("auth response = " + stringObjectMap );
        return stringObjectMap;
    }

    private String getAccessToken(String clientId, String clientSecret) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(COGNITO_TOKEN_URL);

        httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");

        try {
            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("grant_type", "client_credentials"));
            params.add(new BasicNameValuePair("client_id", clientId));
            params.add(new BasicNameValuePair("client_secret", clientSecret));

            httpPost.setEntity(new UrlEncodedFormEntity(params));

            CloseableHttpResponse response = httpClient.execute(httpPost);
            String responseBody = EntityUtils.toString(response.getEntity());

            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(responseBody);

            return jsonNode.get("access_token").asText();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String encodeBase64(String value) {
        return java.util.Base64.getEncoder().encodeToString(value.getBytes());
    }

    private Map<String, Object> generatePolicy(String principalId, String effect, String resource) {
        Map<String, Object> authResponse = new HashMap<>();
        authResponse.put("principalId", principalId);
        Map<String, Object> policyDocument = new HashMap<>();
        policyDocument.put("Version", "2012-10-17"); // default version
        Map<String, String> statementOne = new HashMap<>();
        statementOne.put("Action", "execute-api:Invoke"); // default action
        statementOne.put("Effect", effect);
        statementOne.put("Resource", resource);
        policyDocument.put("Statement", new Object[] {statementOne});
        authResponse.put("policyDocument", policyDocument);
        if ("Allow".equals(effect)) {
            Map<String, Object> context = new HashMap<>();
            context.put("key", "value");
            context.put("numKey", Long.valueOf(1L));
            context.put("boolKey", Boolean.TRUE);
            authResponse.put("context", context);
        }
        return authResponse;
    }
}
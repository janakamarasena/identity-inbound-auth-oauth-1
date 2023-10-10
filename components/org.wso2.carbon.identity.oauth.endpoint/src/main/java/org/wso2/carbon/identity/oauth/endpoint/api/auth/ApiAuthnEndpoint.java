/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.api.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponseData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.OAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthRequest;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthResponse;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Authenticator;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthenticatorMetadata;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.FlowStatusEnum;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Link;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Message;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.NextStep;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Param;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.ParamTypeEnum;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.PromptTypeEnum;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.StepTypeEnum;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Class containing the REST API for API based authentication.
 */
@Path("/authn")
public class ApiAuthnEndpoint {

    private final AuthenticationService authenticationService = new AuthenticationService();
    private final OAuth2AuthzEndpoint oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();
    private static final String AUTHENTICATOR_IDP_SPLITTER = ":";
    private static final String AUTHENTICATOR = "authenticator";
    private static final String IDP = "idp";
    private static final String TENANT_NAME_FROM_CONTEXT = "TenantNameFromContext";
    private static final Log LOG = LogFactory.getLog(ApiAuthnEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/json")
    @Produces("application/json")
    public Response handleAuthentication(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                         String payload) {

        AuthRequest authRequest = buildAuthRequest(payload);
        String authStatus = "unknown";
        try {
            AuthServiceResponse authServiceResponse = authenticationService.handleAuthentication(
                    getAuthServiceRequest(request, response, authRequest));

            //switch case for flow status
            switch (authServiceResponse.getFlowStatus()) {
                case INCOMPLETE:
                    return handleIncompleteAuthResponse(authServiceResponse);
                case FAIL_INCOMPLETE:
                    authStatus = "fail-incomplete";
                    break;
                case SUCCESS_COMPLETED:
                    authStatus = "success-completed";
                    return handleSuccessCompletedAuthResponse(request, response, authServiceResponse);
                case FAIL_COMPLETED:
                    authStatus = "fail-completed";
                    break;
                default:
                    throw new RuntimeException("Unknown flow status"); //TODO: remove
            }

        } catch (AuthServiceException | InvalidRequestParentException | URISyntaxException e) {
            LOG.error("Error while handling authentication", e); //TODO: remove
            throw new RuntimeException(e); // TODO throw oauth error | include state param
        }

        Map<String, String> res = new HashMap<>();
        res.put("status", authStatus);
        return Response.ok().entity(res.toString()).build();
    }

    private AuthRequest buildAuthRequest(String payload) {

        ObjectMapper objectMapper = new ObjectMapper();
        AuthRequest authRequest = null;
        try {
            authRequest = objectMapper.readValue(payload, AuthRequest.class);
        } catch (JsonProcessingException e) {
            LOG.error("Error while handling authentication", e); //TODO: remove
            throw new RuntimeException(e); // TODO throw oauth error | include state param
        }
        return authRequest;
    }

    private Response buildResponse(AuthResponse response) {

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonString = null;
        try {
            jsonString = objectMapper.writeValueAsString(response);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return Response.ok().entity(jsonString).build();
    }

    private AuthServiceRequest getAuthServiceRequest(HttpServletRequest request, HttpServletResponse response,
                                                     AuthRequest authRequest) {

        Map<String, String[]> params = new HashMap<>();
        params.put(OAuthConstants.SESSION_DATA_KEY, new String[]{authRequest.getFlowId()});

        String authenticatorId = authRequest.getSelectedAuthenticator().getAuthenticatorId();
        if (authenticatorId != null) {
            String decodedAuthenticatorId = base64URLDecode(authenticatorId);
            String[] authenticatorIdSplit = decodedAuthenticatorId.split(AUTHENTICATOR_IDP_SPLITTER);

            if (authenticatorIdSplit.length == 2) {
                params.put(AUTHENTICATOR, new String[]{authenticatorIdSplit[0]});
                params.put(IDP, new String[]{authenticatorIdSplit[1]});
            } else {
                throw new RuntimeException("Authenticator id is not in the correct format"); //TODO: remove
            }
        } else {
            throw new RuntimeException("Authenticator id is not provided"); //TODO: remove
        }

        Map<String, String[]> authParams = authRequest.getSelectedAuthenticator().getParams().entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> new String[]{e.getValue()}));
        params.putAll(authParams);

        return new AuthServiceRequest(request, response, params);
    }

    private String base64URLEncode(String value) {

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private String base64URLDecode(String value) {

        return new String(
                Base64.getUrlDecoder().decode(value),
                StandardCharsets.UTF_8);
    }

    private Response handleSuccessCompletedAuthResponse(HttpServletRequest request, HttpServletResponse response,
                                                        AuthServiceResponse authServiceResponse) throws
            InvalidRequestParentException, URISyntaxException {

        String callerSessionDataKey = authServiceResponse.getSessionDataKey();

        Map<String, List<String>> internalParamsList = new HashMap<>();
        // add callerSessionDataKey to internalParamsList map
        internalParamsList.put(OAuthConstants.SESSION_DATA_KEY, Collections.singletonList(callerSessionDataKey));
        OAuthRequestWrapper internalRequest = new OAuthRequestWrapper(request, internalParamsList);
        internalRequest.setInternalRequest(true);

        Response res = oAuth2AuthzEndpoint.authorize(internalRequest, response);
        return buildFinalResponse(res);
    }

    private Response buildFinalResponse(Response res) {

        String redUrl = res.getMetadata().get("Location").get(0).toString();
        Map<String, String> queryParams = getQueryParams(redUrl);
        // queryParams to json string
        String json = new Gson().toJson(queryParams);
        return Response.status(HttpServletResponse.SC_OK).entity(json).build();
    }

    private Map<String, String> getQueryParams(String redirectUrl) {

        Map<String, String> queryParams = new HashMap<>();
        try {
            URI uri = new URI(redirectUrl);
            String query = uri.getQuery();
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                queryParams.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                        URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
            }
        } catch (URISyntaxException | UnsupportedEncodingException e) {
            LOG.error("Error while parsing the redirect url: " + redirectUrl, e);
            throw new RuntimeException(e); // TODO throw oauth error | include state param
        }
        return queryParams;
    }

    private Response handleIncompleteAuthResponse(AuthServiceResponse authServiceResponse) throws AuthServiceException {

        AuthResponse authResponse = new AuthResponse();
        authResponse.setFlowId(authServiceResponse.getSessionDataKey());
        authResponse.setFlowStatus(getFlowStatus(authServiceResponse.getFlowStatus()));
        NextStep nextStep = buildNextStep(authServiceResponse);
        authResponse.setNextStep(nextStep);
        authResponse.setLinks(buildLinks());
        return buildResponse(authResponse);
    }

    private NextStep buildNextStep(AuthServiceResponse authServiceResponse) {

        NextStep nextStep = new NextStep();
        if (!authServiceResponse.getData().isPresent()) {
            throw new RuntimeException("Authenticator data is not present"); //TODO: remove
        }

        AuthServiceResponseData responseData = authServiceResponse.getData().get();
        nextStep.setStepType(getStepType(responseData.isAuthenticatorSelectionRequired()));
        List<Authenticator> authenticators = new ArrayList<>();
        responseData.getAuthenticatorOptions().forEach(authenticatorData -> {
            Authenticator authenticator = buildAuthenticatorData(authenticatorData);
            authenticators.add(authenticator);
        });
        nextStep.setAuthenticators(authenticators);
        List<Message> messages = buildMessages(authServiceResponse);
        nextStep.setMessages(messages);
        nextStep.setAcceptErrorParams(false); //TODO: get from authServiceResponse? remove this?

        return nextStep;
    }

    private Authenticator buildAuthenticatorData(AuthenticatorData authenticatorData) {

        Authenticator authenticator = new Authenticator();
        authenticator.setAuthenticatorId(buildAuthenticatorId(authenticatorData.getName(),
                authenticatorData.getIdp()));
        authenticator.setAuthenticator(authenticatorData.getDisplayName());
        authenticator.setIdp(authenticatorData.getIdp());
        AuthenticatorMetadata metadata = buildAuthenticatorMetadata(authenticatorData);
        authenticator.setMetadata(metadata);

        List<String> requiredAttributes = new ArrayList<>();
        requiredAttributes.add("username"); //TODO: get from authenticatorData
        authenticator.setRequiredParams(requiredAttributes);
        return authenticator;
    }

    private List<Message> buildMessages(AuthServiceResponse authServiceResponse) {

        //TODO: get from authServiceResponse
        List<Message> messages = new ArrayList<>();
        return messages;
    }

    private AuthenticatorMetadata buildAuthenticatorMetadata(AuthenticatorData authenticatorData) {

        AuthenticatorMetadata authenticatorMetadata = new AuthenticatorMetadata();
        //TODO: get from authenticatorData
        authenticatorMetadata.setI18nKey("authenticator." + authenticatorData.getName());
        authenticatorMetadata.setPromptType(getPromptType(authenticatorData));
        List<Param> params = new ArrayList<>();
        authenticatorData.getAuthParams().forEach(paramMetadata -> {
            Param param = buildAuthenticatorParam(paramMetadata);
            params.add(param);
        });
        authenticatorMetadata.setParams(params);
        authenticatorMetadata.setAdditionalData(authenticatorData.getAdditionalData());

        return authenticatorMetadata;
    }

    private Param buildAuthenticatorParam(AuthenticatorParamMetadata paramMetadata) {

        Param param = new Param();
        param.setParam(paramMetadata.getName());
        param.setType(getParamType(paramMetadata.getType()));
        param.setConfidential(paramMetadata.isConfidential());
        param.setOrder(paramMetadata.getParamOrder());
        param.setI18nKey("param." + paramMetadata.getName()); //TODO: get from paramMetadata

        //TODO: regex?
        return param;
    }

    private List<Link> buildLinks() {

        List<Link> links = new ArrayList<>();
        Link authnEpLink = new Link();
        authnEpLink.setName("authentication");
        String endpoint = "/oauth2/authn";
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            endpoint = String.format("/t/%s", getTenantDomainFromContext()) + endpoint;
        }
        String href;
        try {
            href = ServiceURLBuilder.create().addPath(endpoint).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new RuntimeException(e); //TODO: throw oauth error
        }
        authnEpLink.setHref(href);
        authnEpLink.setMethod("POST");
        links.add(authnEpLink);
        return links;
    }

    private String getTenantDomainFromContext() {

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT) != null) {
            tenantDomain = (String) IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT);
        }
        return tenantDomain;
    }

    private String buildAuthenticatorId(String authenticator, String idp) {

        return base64URLEncode(authenticator + AUTHENTICATOR_IDP_SPLITTER + idp);
    }

    private FlowStatusEnum getFlowStatus(AuthServiceConstants.FlowStatus flowStatus) throws
            AuthServiceException {

        switch (flowStatus) {
            case INCOMPLETE:
                return FlowStatusEnum.INCOMPLETE;
            case FAIL_INCOMPLETE:
                return FlowStatusEnum.FAIL_INCOMPLETE;
            case SUCCESS_COMPLETED:
                return FlowStatusEnum.SUCCESS_COMPLETED;
            case FAIL_COMPLETED:
                return FlowStatusEnum.FAIL_COMPLETED;
            default:
                throw new AuthServiceException("Unknown flow status: " + flowStatus +
                        "received from the Authentication Service.");
        }
    }

    private StepTypeEnum getStepType(boolean isMultiOps) {

        if (isMultiOps) {
            return StepTypeEnum.MULTI_OPTIONS_PROMPT;
        } else {
            return StepTypeEnum.AUTHENTICATOR_PROMPT;
        }
    }

    private PromptTypeEnum getPromptType(AuthenticatorData authenticatorData) {

        //TODO: get from authenticatorData
        String promptType = "USER_PROMPT";

        return PromptTypeEnum.fromValue(promptType);
    }

    private ParamTypeEnum getParamType(FrameworkConstants.AuthenticatorParamType authenticatorParamType) {

        // TODO: support other types
        switch (authenticatorParamType) {
            case STRING:
                return ParamTypeEnum.STRING;
            case INTEGER:
                return ParamTypeEnum.NUMBER;
            default:
                throw new RuntimeException("Unknown authenticator param type: " + authenticatorParamType);
        }

    }


}

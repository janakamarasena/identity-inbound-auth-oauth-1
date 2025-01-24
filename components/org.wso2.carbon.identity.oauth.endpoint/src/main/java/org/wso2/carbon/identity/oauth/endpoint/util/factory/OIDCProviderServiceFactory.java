/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.util.factory;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCProcessor;

/**
 * Factory class for OIDCProviderService.
 */
public class OIDCProviderServiceFactory {

    private static final DefaultOIDCProcessor SERVICE;

    static {
        DefaultOIDCProcessor oidcProviderService = (DefaultOIDCProcessor) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OIDCProcessor.class, null);

        if (oidcProviderService == null) {
            throw new IllegalStateException("OIDCProviderService is not available from OSGI context.");
        }
        SERVICE = oidcProviderService;
    }

    public static DefaultOIDCProcessor getOIDCService() {

        return SERVICE;
    }
}
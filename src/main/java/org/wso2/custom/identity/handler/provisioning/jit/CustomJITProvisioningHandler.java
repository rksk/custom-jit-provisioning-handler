package org.wso2.custom.identity.handler.provisioning.jit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.JITProvisioningPostAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.custom.identity.handler.provisioning.jit.internal.ProvisioningHandlerServiceComponent;

import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;

/**
 * A custom JIT provisioning handler to generate a random UUID for the username when external users
 * getting provisioned in the JustInTime provisioning flow.
 */
public class CustomJITProvisioningHandler extends JITProvisioningPostAuthenticationHandler {

    private static final Log log = LogFactory.getLog(CustomJITProvisioningHandler.class);
    private static volatile CustomJITProvisioningHandler instance;

    private static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";

    public static CustomJITProvisioningHandler getInstance() {
        if (instance == null) {
            synchronized (CustomJITProvisioningHandler.class) {
                if (instance == null) {
                    instance = new CustomJITProvisioningHandler();
                }
            }
        }
        return instance;
    }

    @Override
    public int getPriority() {

        int priority = super.getPriority();
        if (priority == -1) {
            priority = 21;
        }
        return priority;
    }

    @Override
    public String getName() {

        return "CustomJITProvisionHandler";
    }

    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest request, HttpServletResponse response,
                                             AuthenticationContext context) throws PostAuthenticationFailedException {

        if (!FrameworkUtils.isStepBasedSequenceHandlerExecuted(context)) {
            return SUCCESS_COMPLETED;
        }

        Object isUIRedirectionTriggered = context
                .getProperty(FrameworkConstants.PASSWORD_PROVISION_REDIRECTION_TRIGGERED);
        if (isUIRedirectionTriggered == null || !((boolean) isUIRedirectionTriggered)) {

            SequenceConfig sequenceConfig = context.getSequenceConfig();
            for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
                StepConfig stepConfig = entry.getValue();
                AuthenticatorConfig authenticatorConfig = stepConfig.getAuthenticatedAutenticator();
                if (authenticatorConfig == null) {
                    continue;
                }
                ApplicationAuthenticator authenticator = authenticatorConfig.getApplicationAuthenticator();

                if (authenticator instanceof FederatedApplicationAuthenticator) {
                    ExternalIdPConfig externalIdPConfig;
                    String externalIdPConfigName = stepConfig.getAuthenticatedIdP();
                    externalIdPConfig = getExternalIdpConfig(externalIdPConfigName, context);
                    Map<String, String> localClaimValues = (Map<String, String>) context
                            .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);
                    if (localClaimValues == null || localClaimValues.size() == 0) {
                        Map<ClaimMapping, String> userAttributes =
                                stepConfig.getAuthenticatedUser().getUserAttributes();
                        localClaimValues = FrameworkUtils.getClaimMappings(userAttributes, false);
                    }

                    if (externalIdPConfig != null && externalIdPConfig.isProvisioningEnabled()) {

                        if (localClaimValues.get(EMAIL_CLAIM) == null) {
                            String errorMsg = "No email address received.";
                            log.error(errorMsg);
                            throw new PostAuthenticationFailedException(errorMsg, errorMsg);
                        }

                        String tenantDomain = context.getTenantDomain();
                        String userEmail = localClaimValues.get(EMAIL_CLAIM);
                        String associatedLocalUser = getUsernameFromEmail(userEmail, tenantDomain);

                        if (associatedLocalUser == null) {
                            // Creating a new UUID since no local user found with the same username
                            sequenceConfig.getAuthenticatedUser().setUserName(UUID.randomUUID().toString());
                        } else {
                            // Updating the subject with the existing username who has the same email
                            sequenceConfig.getAuthenticatedUser().setUserName(associatedLocalUser);
                        }

                        // No need to check further since we will be setting another UUID
                        break;
                    }
                }
            }
        }

        return super.handle(request, response, context);
    }

    private String getUsernameFromEmail(String userEmail, String tenantDomain)
            throws PostAuthenticationFailedException {

        RealmService realmService = ProvisioningHandlerServiceComponent.getRealmService();

        try {
            int usersTenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserRealm userRealm = (UserRealm) realmService.getTenantUserRealm(usersTenantId);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            String[] userList = userStoreManager.getUserList(EMAIL_CLAIM, userEmail, null);

            if (userList == null || userList.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("No user found with the provided email: " + userEmail);
                }
            } else if (userList.length == 1) {
                if (log.isDebugEnabled()) {
                    log.debug("Found single user " + userList[0] + " with the email: " + userEmail);
                }
                return userList[0];
            } else {
                String errorMsg = "Multiple users found with the provided email: " + userEmail;
                log.error(errorMsg);
                throw new PostAuthenticationFailedException(errorMsg, errorMsg);
            }
        } catch (UserStoreException e) {
            String errorMsg = "Provisioning failed for the email: " + userEmail;
            log.error(errorMsg, e);
            throw new PostAuthenticationFailedException(errorMsg, errorMsg);
        }

        return null;
    }


    private ExternalIdPConfig getExternalIdpConfig(String externalIdPConfigName, AuthenticationContext context)
            throws PostAuthenticationFailedException {

        ExternalIdPConfig externalIdPConfig = null;

        try {
            externalIdPConfig = ConfigurationFacade.getInstance().getIdPConfigByName(externalIdPConfigName,
                    context.getTenantDomain());
        } catch (IdentityProviderManagementException e) {
            this.handleExceptions(String.format(
                    FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_GETTING_IDP_BY_NAME.getMessage(),
                    externalIdPConfigName, context.getTenantDomain()),
                    FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_GETTING_IDP_BY_NAME.getCode(), e);
        }

        return externalIdPConfig;
    }

    private void handleExceptions(String errorMessage, String errorCode, Exception e)
            throws PostAuthenticationFailedException {

        throw new PostAuthenticationFailedException(errorCode, errorMessage, e);
    }

}

package org.wso2.custom.identity.handler.provisioning.jit;

import org.wso2.carbon.identity.application.authentication.framework.handler.provisioning.impl.DefaultProvisioningHandler;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;

import java.util.ArrayList;
import java.util.List;

/**
 * Custom provisioning handler to avoid local roles getting removed when the user logs in with the federated IdP for
 * the second time.
 */
public class CustomProvisioningHandler extends DefaultProvisioningHandler {

    protected List<String> retrieveRolesToBeDeleted(UserRealm realm, List<String> currentRolesList,
                                                    List<String> rolesToAdd) throws UserStoreException {

        // we are returning an empty list here to avoid local roles getting overridden
        return new ArrayList<String>();
    }
}

package org.wso2.custom.identity.handler.provisioning.jit.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthenticationHandler;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.custom.identity.handler.provisioning.jit.CustomJITProvisioningHandler;

@Component(
        name = "org.wso2.custom.identity.handler.provisioning.jit",
        immediate = true
)
public class ProvisioningHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(ProvisioningHandlerServiceComponent.class);
    private static RealmService realmService = null;

    public static RealmService getRealmService() {
        return realmService;
    }

    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the CustomProvisioningHandler bundle");
        }
        this.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the CustomProvisioningHandler bundle");
        }
        this.realmService = null;
    }

    @Activate
    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();
        CustomJITProvisioningHandler customJITProvisioningHandler = CustomJITProvisioningHandler.getInstance();
        bundleContext.registerService(PostAuthenticationHandler.class.getName(), customJITProvisioningHandler, null);
        if (log.isDebugEnabled()) {
            log.debug("Activating CustomProvisioningHandler Service Component");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("CustomProvisioningHandler bundle is deactivated");
        }
    }

}



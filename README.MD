This custom JIT provisioning handler is developed to generate a random UUID for the username when external users getting provisioned in the JustInTime provisioning flow. The email address is being used as the unique attribute to identify already provisioned users.

Steps to deploy the custom JIT provisioning handler.

1. Build the component using `mvn clean install"
2. Copy the "org.wso2.custom.identity.handler.provisioning.jit-1.0.0.jar" from target directory into <IS_HOME>/repository/components/dropins
3. Add following lines into deployment.toml
```
[event.default_listener.jit_provisioning_handler]
enable = false

[[event_listener]]
id = "custom_jit_provisioning_handler"
type = "org.wso2.carbon.identity.core.handler.AbstractIdentityHandler"
name = "org.wso2.custom.identity.handler.provisioning.jit.CustomJITProvisioningHandler"
order = "21"
enable = "true"
```

Additionally, if you need to avoid local roles getting removed when user logs in with the federated IdP for the second time, following config can be used.
```
[authentication.framework.extensions]
provisioning_handler = "org.wso2.custom.identity.handler.provisioning.jit.CustomProvisioningHandler"
```
4. Restart WSO2 IS
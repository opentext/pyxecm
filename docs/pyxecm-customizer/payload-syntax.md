# Payload Syntax

## Customizing General

The customizing payload can be defined in either of the following standards:

- [Terraform / HCL](https://developer.hashicorp.com/terraform/language/expressions/types)
- [YAML](https://yaml.org/spec/1.2.2/)

=== "Terraform / HCL"

    The Terraform language uses the following types for its values:

    - `string`: a sequence of Unicode characters representing some text, like `"hello"`.
    - `number`: a numeric value. The number type can represent both whole numbers like 15 and fractional values like `6.283185`.
    - `bool`: a boolean value, either `true` or `false` (lowercase!). bool values can be used in conditional logic.
    - `list (or tuple)`: a sequence of values, like `["user1", "user2"]`.
    - `map (or dictionary)`: a group of values identified by named labels, like `{name = "nwheeler", security_clearance = 50}`.

    Most of the customizing settings may have an optional field called `enabled` that allows to dynamically turn on / off customization settings based on a boolean value that may be read from a Terraform variable (or could just be `false` or `true`). In case you are using additional external payload (see above) you need to provide `false` or `true` directly. If `enabled` is not specified then `enabled = True` is assumed (this is the default).

=== "YAML"

    The YAML language uses the following types for its values:

    - `string`: a sequence of Unicode characters representing some text, like `hello`.
    - `number`: a numeric value. The number type can represent both whole numbers like 15 and fractional values like `6.283185`.
    - `bool`: a boolean value, either `true` or `false`.
    - `list`: a sequence of values, like `["user1", "user2"]` or
      ```yaml
      - name: user1
      - name: user2
      ```
    - `dictionary`: a group of values identified by named labels, like `{name: nwheeler, security_clearance: 50}`.
      ```yaml
        name: nwheeler
        security_clearance: 50
      ```

    Sample usage:
      ```yaml
      users:
        - name: nwheeler
          security_clearance: 50
        - name: adminton
          security_clearance: 90
      ```

    Most of the customizing settings may have an optional field called `enabled` that allows to dynamically turn on / off customization settings based on a boolean value. If `enabled` is not specified then `enabled = True` is assumed (this is the default).

## payloadOptions

This section defines options that are used to manage the payload. This is only required when using the Customizer as a Service (API).

=== "Terraform / HCL"

    ```terraform
    payloadOptions = {
        enabled = true
        name = "Name of the Payload Object"
        dependencies = ["Name of Payload item #1 it depends on","Name of Payload item #2 it depends on", ...]
        loglevel = "INFO" # DEBUG, INFO, WARNING, ERROR
    }
    ```

## payloadSections

This section defines the payload sections that are used and defines the order in which they are processed.
Only the sections listed here are processed. If a payload has no `payloadSections`, nothing is processed.

Each list element is a dictionary with these fields:

- `name` (str, mandatory) - the name of the payload section, for example `groups` or `transportPackages`
- `enabled` (bool) - set to `true` to process the section. The data of a section is only loaded if its entry in
  `payloadSections` has `enabled = true`, so always set this value explicitly.
- `restart` (bool, optional, default = `false`) - restart the Content Management frontend and backend services
  after this section has been processed

The entry for the `users` section supports these additional fields:

- `additional_instances` (int, optional, default = `0`) - create additional copies of all users in the `users`
  section. The copies get a two-digit number as suffix of the login name and the last name.
- `user_customization` (bool, optional, default = `true`) - process the user profile photos (and related
  user customizations) after the users have been created
- `jato_enabled` (bool, optional, default = `true`) - use the `jato` Smart View theme for the user profiles
  (otherwise the `cf` theme is used)

=== "Terraform / HCL"

    ```terraform
    payloadSections = [
      { name = "adminSettings", enabled = true },
      { name = "groups", enabled = true },
      { name = "users", enabled = true, additional_instances = 0 },
      { name = "webReports", enabled = true },
      { name = "transportPackages", enabled = true, restart = true },
      { name = "permissions", enabled = true },
    ]
    ```

=== "YAML"

    ```yaml
    payloadSections:
    - name: adminSettings
      enabled: true
    - name: groups
      enabled: true
    - name: users
      enabled: true
      additional_instances: 0
    - name: webReports
      enabled: true
    - name: transportPackages
      enabled: true
      restart: true
    - name: permissions
      enabled: true
    ```

### Post sections

Some sections exist a second time with the suffix `Post`: `groupsPost`, `usersPost`, `adminSettingsPost`,
`transportPackagesPost`, `itemsPost`, `permissionsPost`, `webReportsPost`, `webHooksPost`, `sapRFCsPost`,
and `browserAutomationsPost`. A `Post` section uses exactly the same syntax as the section without the suffix. It
is a separate payload key with its own data, so the same kind of configuration can be applied at a second point in
time, typically after the transport packages have been deployed. Like every other section, a `Post` section is only
processed if it is listed in `payloadSections`; its position in that list defines when it is processed.

=== "Terraform / HCL"

    ```terraform
    groupsPost = [
      {
        name = "Contract Managers"
      }
    ]

    payloadSections = [
      { name = "groups", enabled = true },
      { name = "transportPackages", enabled = true },
      { name = "groupsPost", enabled = true },
    ]
    ```

=== "YAML"

    ```yaml
    groupsPost:
    - name: Contract Managers

    payloadSections:
    - name: groups
      enabled: true
    - name: transportPackages
      enabled: true
    - name: groupsPost
      enabled: true
    ```

### OTDS Customizing Syntax

The payload syntax for OTDS customizing uses the following lists (the list elements are maps):

#### resources

`resources` allows to create new resources in OTDS.

Each list element includes a switch `enabled` to turn them on or off. This switch can be controlled by a Terraform variable.

In addition, each resource definition has a `name`, an optional `description`, and an optional `display_name`. It is also possible to activate the new resource via the `activate = true`. With `resource_id` and `secret` pre-defined values can be provided for the resource ID and the secret. The `secret` should be 24 characters long and end with `==`. If a secret and a resource ID are provided, then the resource is automatically activated. Otherwise you can enforce activation with `activate = true`. With `additional_payload` a dictionary of key value pairs can be provided:

=== "Terraform / HCL"

    ```terraform
    resources = [
      {
        enabled             = true
        name                = "Aviator Search"
        description         = "Resource for Aviator Search"
        display_name        = "Resource for Aviator Search"
        allow_impersonation = true
        activate            = true # if a secret is provided the resource will automatically be activated
        resource_id         = "a331e5cb-68ef-4cb7-a8a0-037ba6b35522"
        secret              = "0123456789012345678901==" # needs to end with ==
        additional_payload  = {
          "pcCreatePermissionAllowed": true,
          "pcModifyPermissionAllowed": true,
          "pcDeletePermissionAllowed": false,
        }
      }
    ]
    ```

=== "YAML"

    ```yaml
    resources:
      - enabled: True
        name: "Aviator Search"
        description: "Resource for Aviator Search"
        display_name: "Resource for Aviator Search"
        allow_impersonation: True
        activate: True
        resource_id: "a331e5cb-68ef-4cb7-a8a0-037ba6b35522"
        secret: "0123456789012345678901==" # needs to end with ==
        additional_payload:
        ...
    ```

#### synchronized partition

`synchronized partition` allows to create a new synchronized partition in otds

Each list element includes a switch `enabled` to turn them on or off. This switch can be controlled by a Terraform variable.

In addition, the name of each synchronized partition is taken from `profileName` in `spec` and the optional description from `description` in `spec`. It is also possible to directly put the new synchronized partition into an existing `access_role`. Also `licenses` this synchronized partition should be assigned to can be specified:

In case of importing Active Directory users and groups ignore licenses.

=== "Terraform / HCL"

    ```terraform
    synchronizedPartitions = [
      {
        access_role = "Access to cs"
        licenses = ["X2", "ADDON_AVIATOR", "ADDON_MEDIA"]
        spec = {
          "ipConnectionParameter": [
            {
              "hostName": host,
              "portNumber": port,
              "encryptionMethod": 0
            }
          ],
          "ipAuthentication": {
            "bindDN": user,
            "authenticationMethod": 1,
            "qualityOfProtection": 0,
            "bindPassword": "password need to be sent from secrets and set it to my_customizer.otds_settings.bindPassword " 
            "servicePrincipalName": "ldap/undefined",
            "kerberosCredentialType": 0
          },
          "objectClassNameMapping": [
            {
              "objectType": 0,
              "destObject": "oTPerson",
              "sourceFilter": "(|(objectClass=organizationalPerson)(objectClass=posixAccount))",
              "attributeMapping": [
                {
                  "sourceAttr": [
                    "cn"
                  ],
                  "destAttr": "cn",
                  "mappingFormat": "%s"
                },
                {
                  "sourceAttr": [
                    ""
                  ],
                  "destAttr": "oTDepartment",
                  "mappingFormat": "[Tenant Administrators Group]"
                },
                {
                  "sourceAttr": [
                    ""
                  ],
                  "destAttr": "oTType",
                  "mappingFormat": "TenantAdminUser"
                }
              ],
              "syncPairMapping": [
                {
                  "sourceLocation": "ou=People,ou=WEM1672,dc=opentext,dc=com",
                  "recurse": 1
                }
              ],
              "mustMappedAttributes": [
                "cn"
              ]
            },
            {
              "objectType": 1,
              "destObject": "oTGroup",
              "sourceFilter": "(objectClass=groupOfUniqueNames)",
              "attributeMapping": [
                {
                  "sourceAttr": [
                    "cn"
                  ],
                  "destAttr": "cn",
                  "mappingFormat": "%s"
                },
                {
                  "sourceAttr": [
                    ""
                  ],
                  "destAttr": "oTType",
                  "mappingFormat": "TenantAdminUser"
                }
              ],
              "syncPairMapping": [
                {
                  "sourceLocation": "ou=Groups,ou=WEM1672,dc=opentext,dc=com",
                  "recurse": 1
                }
              ],
              "mustMappedAttributes": [
                "cn"
              ]
            }
          ],
          "basicAttributes": [
            {
              "attrId": "externalIDType",
              "attrValues": [
                "0"
              ]
            },
            {
              "attrId": "externalIDAttribute",
              "attrValues": [
                "mail"
              ]
            },
            {
              "attrId": "importUsersFromMatchedGroups",
              "attrValues": [
                "0"
              ]
            },
            {
              "attrId": "oTSearchFilterUsersAttributes",
              "attrValues": [
                ""
              ]
            },
            {
              "attrId": "oTSearchFilterGroupsAttributes",
              "attrValues": [
                ""
              ]
            },
            {
              "attrId": "fullSyncSchedule",
              "attrValues": [
                "0 0 0 1,2,3,4,5,6,7"
              ]
            }
          ],
          "basicInfo": {
            "enableUUIDTracking": true,
            "externalIDAttribute": "mail",
            "groupLoginAttr": "cn",
            "memberAttr": [
              "uniqueMember",
              "member"
            ],
            "monitorChanges": true,
            "monitoringFullSyncStartTime": "0000",
            "monitoringPingTime": 5,
            "monitoringType": "2",
            "objectUUIDAttribute": "nsUniqueId",
            "pagedSearchPageSize": 200,
            "schemaType": 6,
            "searchType": "1",
            "supportDirSyncControl": false,
            "supportedSASLMechanisms": "(2): EXTERNAL; DIGEST-MD5",
            "supportPagedSearchControl": false,
            "supportPersistentSearchControl": true,
            "supportUnlimitedSearch": false,
            "supportUSNQuery": false,
            "supportVLVControl": true,
            "userLoginAttr": "uid",
            "vlvsearchPageSize": "200",
            "vlvsortingAttribute": "entryDN"
          },
          "baseDN": "dc=opentext,dc=com",
          "profileName": "csActiveDirectory",
          "description": "Partition contains Active Directory users and groups",
          "ipSchemaType": 6,
          "authProvider": 1
        }
      }
    ]
    ```

=== "YAML"

    ```yaml
    synchronizedPartitions:
    - access_role: "Access to cs"
      spec:
        ipConnectionParameter:
        - hostName: hostname
          portNumber: port
          encryptionMethod: 0

        ipAuthentication:
          bindDN: user
          authenticationMethod: 1
          qualityOfProtection: 0
          bindPassword: ## password need to be sent from secrets and set it to my_customizer.otds_settings.bindPassword 
          servicePrincipalName: ldap/undefined
          kerberosCredentialType: 0

        objectClassNameMapping:
          - objectType: 0
            destObject: oTPerson
            sourceFilter: (|(objectClass=organizationalPerson)(objectClass=posixAccount))
            ## add all the required attributes as mentioned in below format
            attributeMapping:
              - sourceAttr: ["cn"]
                destAttr: cn
                mappingFormat: '%s'
              - sourceAttr: [""]
                destAttr: oTDepartment
                mappingFormat: "[Tenant Administrators Group]" 
              - sourceAttr: [""]
                destAttr: oTType
                mappingFormat: TenantAdminUser
            syncPairMapping:
              - sourceLocation: "ou=People,ou=WEM1672,dc=opentext,dc=com"
                recurse: 1
            mustMappedAttributes: ["cn"]
          - objectType: 1
            destObject: oTGroup
            sourceFilter: (objectClass=groupOfUniqueNames)
            ## add all the required attributes as mentioned in below format
            attributeMapping:
              - sourceAttr: ["cn"]
                destAttr: cn
                mappingFormat: '%s'
              - sourceAttr: [""]
                destAttr: oTType
                mappingFormat: TenantAdminUser
            syncPairMapping:
              - sourceLocation: "ou=Groups,ou=WEM1672,dc=opentext,dc=com"
                recurse: 1
            mustMappedAttributes: ["cn"]
        basicAttributes:
          - attrId: externalIDType
            attrValues: ["0"]
          - attrId: externalIDAttribute
            attrValues: ["mail"]
          - attrId: importUsersFromMatchedGroups
            attrValues: ["0"]
          - attrId: oTSearchFilterUsersAttributes
            attrValues: [""]
          - attrId: oTSearchFilterGroupsAttributes
            attrValues: [""]
          - attrId: fullSyncSchedule
            attrValues: ["0 0 0 1,2,3,4,5,6,7"]
        basicInfo:
          enableUUIDTracking: true
          externalIDAttribute: mail
          groupLoginAttr: cn
          memberAttr:
            - uniqueMember
            - member
          monitorChanges: true
          monitoringFullSyncStartTime: '0000'
          monitoringPingTime: 5
          monitoringType: '2'
          objectUUIDAttribute: nsUniqueId
          pagedSearchPageSize: 200
          schemaType: 6
          searchType: '1'
          supportDirSyncControl: false
          supportedSASLMechanisms: '(2): EXTERNAL; DIGEST-MD5'
          supportPagedSearchControl: false
          supportPersistentSearchControl: true
          supportUnlimitedSearch: false
          supportUSNQuery: false
          supportVLVControl: true
          userLoginAttr: uid
          vlvsearchPageSize: '200'
          vlvsortingAttribute: entryDN

        baseDN: dc=opentext,dc=com
        profileName: csActiveDirectory
        description: "Partition contains Active Directory users and groups"
        ipSchemaType: 6
        authProvider: 1
    ```

#### partitions

`partitions` allows to create new partitions in OTDS.

Each list element includes a switch `enabled` to turn them on or off. This switch can be controlled by a Terraform variable.

In addition, each partition has a `name`, an optional `description`. It is also possible to directly put the new partition into an existing `access_role`. Also `licenses` this partition should be assigned to can be specified:

=== "Terraform / HCL"

    ```terraform
    partitions = [
      {
          enabled     = true
          name        = "Salesforce"
          description = "Salesforce user partition"
          access_role = "Access to cs"
          licenses    = ["X2", "ADDON_AVIATOR", "ADDON_MEDIA"]
      }
    ]
    ```

=== "YAML"

    ```yaml
    partitions:
      - enabled: True
        name: "Salesforce"
        description: "Salesforce user partition"
        access_role: "Access to cs"
        licenses:
        - "X2"
        - "ADDON_AVIATOR"
        - "ADDON_MEDIA"
    ```

#### licenses

`licenses` allows to assign a license to a resource.

Each list element includes a switch `enabled` to turn them on or off. This switch can be controlled by a Terraform variable.

=== "Terraform / HCL"

    ```terraform
    licenses = [
      {
        enabled      = true
        path         = "/payload/otawp-license.lic"
        product_name = "APPWORKS_PLATFORM"
        resource     = "awp"
        description  = "License for Appworks Platform"
      }
    ]
    ```

=== "YAML"

    ```yaml
    licenses:
      - enabled: True
        path: "/payload/otawp-license.lic"
        product_name: "APPWORKS_PLATFORM"
        resource: "awp"
        description: "License for Appworks Platform"
    ```

#### oauthClients

`oauthClients` allows to create a list of new OAuth client in OTDS.

Each list element includes a switch `enabled` to turn them on or off. This switch can be controlled by a Terraform variable.

`name` defines the name of the OTDS OAuth client and `description` should describe what the OAuth client is used for. Each OAuth client has the typical elements such as `confidential` (default is `true`), OTDS `partition` (default is `Global`), `redirect_urls`, `permission_scopes`, `default_scopes`, and `allow_impersonation`. If there's a predefined secret it can be provided by `secret`. The user_type of the user in Content Server can be changed, default is "", which is a standard user. It can be changed to "ServiceUser".

=== "Terraform / HCL"

    ```terraform
    oauthClients = [
      {
        enabled             = var.enable_salesforce
        name                = "salesforce"
        description         = "OAuth client for Salesforce"
        confidential        = true
        partition           = "Global"
        redirect_urls       = ["https://salesforce.com/services/authcallback/OTDS"]
        permission_scopes   = ["full"]
        default_scopes      = ["full"]
        allow_impersonation = true
        secret              = var.salesforce_oauth_secret
        user_type           = "ServiceUser"
      }
    ]
    ```

=== "YAML"

    ```yaml
      oauthClients:
      - allow_impersonation: true
        confidential: true
        default_scopes:
        - full
        description: OAuth client for Salesforce
        enabled: ${var.enable_salesforce}
        name: salesforce
        partition: Global
        permission_scopes:
        - full
        redirect_urls:
        - https://salesforce.com/services/authcallback/OTDS
        secret: ${var.salesforce_oauth_secret}
        user_type: "ServiceUser"
    ```

#### authHandlers

`authHandlers` is a list of additional OTDS authentication handlers.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, each handler has a `name`, `type` and an optional `description`. Further values can be specified that depends on the type of the handler. Supported types are `SAML`, `OAUTH`, or `SAP`. The values can also use terraform variables.

Optional keys for all handler types:

- `scope` (str) - name of the user partition that limits the scope of the handler
- `priority` (int) - priority of the handler compared to other handlers
- `active_by_default` (bool, default = `false`) - redirect to the identity provider immediately instead of showing the OTDS login page

Additional optional keys for `SAML` handlers:

- `auth_principal_attributes` (list) - list of authentication principal attributes
- `nameid_format` (str) - NameID format of the identity provider that contains the user identifier

=== "Terraform / HCL"

    ```terraform
    authHandlers = [
      {
        enabled                = true
        name                   = "..."
        description            = "..."
        type                   = "..." # either SAML, OAUTH, or SAP
        provider_name          = "..." # required for SAML and OAUTH
        saml_url               = "..." # required for SAML
        otds_sp_endpoint       = "https://${local.otds_dns_name}/otdsws/login" # required for SAML
        certificate_file       = "..." # required only for SAP
        certificate_password   = "..." # required only for SAP
        client_id              = "..." # required only for OAUTH
        client_secret          = "..." # required only for OAUTH
        active_by_default      = false # replace standard OTDS login page
        authorization_endpoint = "..." # required only for OAUTH
        token_endpoint         = "..." # required only for OAUTH
        scope_string           = "id"
      },
    ]
    ```

=== "YAML"

    ```yaml
      authHandlers:
      - active_by_default: false
        authorization_endpoint: '...'
        certificate_file: '...'
        certificate_password: '...'
        client_id: '...'
        client_secret: '...'
        description: '...'
        enabled: true
        name: '...'
        otds_sp_endpoint: https://${local.otds_dns_name}/otdsws/login
        provider_name: '...'
        saml_url: '...'
        scope_string: '...'
        token_endpoint: '...'
        type: '...'
    ```

#### trustedSites

`trustedSites` allows you to define trusted sites for OTDS.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

The actual URL for the trusted site is given by the field `url`. Regular expressions are allowed to define patterns for the URL.

=== "Terraform / HCL"

    ```terraform
    trustedSites = [
      {
        enabled = var.enable_successfactors
        url     = "https://[^/]+\\.successfactors\\.eu/.*"
      },
      {
        enabled = var.enable_successfactors
        url     = "https://[^/]+\\.successfactors\\.com/.*"
      },
      {
        enabled = var.enable_salesforce
        url     = "https://[^/]+\\.salesforce\\.com/.*"
      },
      {
        enabled = var.enable_salesforce
        url     = "https://[^/]+\\.force\\.com/.*"
      },
      {
        enabled = var.enable_o365
        url     = "https://[^/]+\\.microsoft\\.com/.*"
      },
      {
        enabled = var.enable_o365
        url     = "https://[^/]+\\.sharepoint\\.com/.*"
      },
      {
        enabled = var.enable_o365
        url     = "https://[^/]+\\.office\\.com/.*"
      },
      {
        enabled = var.enable_appworks
        url     = "https://${local.otawp_dns_name}" # AppWorks endpoint
      },
    ]
    ```

=== "YAML"

    ```yaml
    trustedSites:
    - enabled: ${var.enable_successfactors}
      url: https://[^/]+\\.successfactors\\.eu/.*
    - enabled: ${var.enable_successfactors}
      url: https://[^/]+\\.successfactors\\.com/.*
    - enabled: ${var.enable_salesforce}
      url: https://[^/]+\\.salesforce\\.com/.*
    - enabled: ${var.enable_salesforce}
      url: https://[^/]+\\.force\\.com/.*
    - enabled: ${var.enable_o365}
      url: https://[^/]+\\.microsoft\\.com/.*
    - enabled: ${var.enable_o365}
      url: https://[^/]+\\.sharepoint\\.com/.*
    - enabled: ${var.enable_o365}
      url: https://[^/]+\\.office\\.com/.*
    - enabled: ${var.enable_appworks}
      url: https://${local.otawp_dns_name}
    ```

#### systemAttributes

`systemAttributes` allows you to set system attributes in OTDS.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, each system attribute has a `name`, `value` and an optional `description`.

=== "Terraform / HCL"

    ```terraform
    systemAttributes = [
      {
        enabled     = true
        name        = "otds.as.SameSiteCookieVal"
        value       = "None"
        description = "SameSite Cookie Attribute"
      }
    ]
    ```

=== "YAML"

    ```yaml
    systemAttributes:
    - description: SameSite Cookie Attribute
      enabled: true
      name: otds.as.SameSiteCookieVal
      value: None
    ```

#### additionalGroupMemberships

`additionalGroupMemberships` allows adding pre-existing users or groups to existing OTDS groups. Each list element can include an `enabled` switch to turn the item on or off (default is `true`).

Each element consists of a `parent_group` value combined with either a `group_name` or `user_name` value.

=== "Terraform / HCL"

    ```terraform
    additionalGroupMemberships = [
      {
        parent_group = "Business Administrators@Content Server Members"
        user_name    = "otadmin@otds.admin"
      }
    ]
    ```

=== "YAML"

    ```yaml
    additionalGroupMemberships:
    - parent_group: Business Administrators@Content Server Members
      user_name: otadmin@otds.admin
    ```

#### additionalAccessRoleMemberships

`additionalAccessRoleMemberships` allows adding pre-existing users, groups, or partitions to existing OTDS Access Roles.

Each list element can include an `enabled` switch to turn the item on or off (default is `true`).

Each element consists of an `access_role` value combined with either a `group_name`, `user_name`, or `partition_name` value.

=== "Terraform / HCL"

    ```terraform
    additionalAccessRoleMemberships = [
      {
        access_role = "Access to cs"
        group_name  = "otdsadmins@otds.admin"
      },
      {
        # Add the Content Server Members partition to the AppworksGateway access role
        enabled        = var.enable_appworks_gateway
        access_role    = "Access to gatewayresource"
        partition_name = "Content Server Members"
      }
    ]
    ```

=== "YAML"

    ```yaml
    additionalAccessRoleMemberships:
    - access_role: Access to cs
      group_name: otdsadmins@otds.admin
    - access_role: Access to gatewayresource
      enabled: ${var.enable_appworks_gateway}
      partition_name: Content Server Members
    ```

#### additionalApplicationRoleAssignments

`additionalApplicationRoleAssignments` allows adding pre-existing users or groups to existing OTDS application roles.

Each list element can include an `enabled` switch to turn the item on or off (default is `true`).

Each element should include:

- `role_name` (required): either `role` or `role@partition`.
- `user_name` (optional): user to assign (mutually exclusive with `group_name`).
- `group_name` (optional): group to assign (mutually exclusive with `user_name`).

=== "Terraform / HCL"

    ```terraform
    additionalApplicationRoleAssignments = [
      {
        role_name = "WorkflowDesigner@OAuthClients"
        user_name = "otadmin@otds.admin"
      },
      {
        role_name  = "WorkflowDesigner@OAuthClients"
        group_name = "otdsadmins@otds.admin"
      }
    ]
    ```

=== "YAML"

    ```yaml
    additionalApplicationRoleAssignments:
    - role_name: WorkflowDesigner@OAuthClients
      user_name: otadmin@otds.admin
    - role_name: WorkflowDesigner@OAuthClients
      group_name: otdsadmins@otds.admin
    ```

#### applicationRoles

`applicationRoles` creates application roles in OTDS.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `name` (str, mandatory) - name of the application role
- `description` (str, optional) - description of the application role
- `partition` (str, optional, default = `OAuthClients`) - name of the OTDS partition the role is created in
- `values` (list, optional) - additional values passed to OTDS when the role is created
- `custom_attributes` (list, optional) - custom attributes passed to OTDS when the role is created

=== "Terraform / HCL"

    ```terraform
    applicationRoles = [
      {
        enabled     = true
        name        = "WorkflowDesigner"
        description = "Users who can design workflows"
        partition   = "OAuthClients"
      }
    ]
    ```

=== "YAML"

    ```yaml
    applicationRoles:
    - enabled: true
      name: WorkflowDesigner
      description: Users who can design workflows
      partition: OAuthClients
    ```

### Content Management Customizing Syntax

The payload syntax for Content Management configurations uses these lists (list elements are maps / dictionaries):

#### groups

`groups` is a list of Content Management user groups that are automatically created during the deployment.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, each group has a `name` and (optionally) a list of parent groups. `enable_o365`, `enable_salesforce`, and `enable_core_share` are used to control whether or not a Microsoft 365, Salesforce or Core Share group should be created matching the OpenText Content Management group. The example below shows two groups. The `Finance` group is a child group of the `Innovate` group. The `Finance` group is also created in Microsoft 365 if the variable `var.enable_o365` evaluates to `true`.

=== "Terraform / HCL"

    ```terraform
    groups = [
      {
        enabled           = true
        name              = "Innovate"
        parent_groups     = []
      },
      {
        enabled           = true
        name              = "Finance"
        parent_groups     = ["Innovate"]
        enable_o365       = var.enable_o365
        enable_salesforce = var.enable_salesforce
        enable_core_share = var.enable_core_share
      }
    ]
    ```

=== "YAML"

    ```yaml
    groups:
    - name: Innovate
      parent_groups: []
    - enable_o365: ${var.enable_o365}
      enable_salesforce: ${var.enable_salesforce}
      enable_core_share: ${var.enable_core_share}
      name: Finance
      parent_groups:
      - Innovate
    ```

#### users

`users` is a list of OpenText Content Management users that are automatically created during deployment.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, users should have `name`, `password`, `firstname`, `lastname`, `email`, `title`, and `company`. The `password` of these users can also be randomly generated and can be printed by `terraform output -json` (all users have the same password). Each user needs to have a base group that must be in the `groups` section of the payload. Optionally a user can have a list of additional groups. A user can also have a list of favorites. Favorites can either be the logical name of a workspace instance used in the payload (see workspace below) or it can be a nickname of an OpenText Content Management item. Users can also have a **security clearance level** and multiple **supplemental markings**. Both are optional. `security_clearance` is used to define the security clearance level of the user. This needs to match one of the existing security clearance levels that have been defined in the `securityClearances` section in the payload. `supplemental_markings` defines a list of supplemental markings the user should get. These need to match markings defined in the `supplementalMarkings` section in the payload. The field `privileges` defines the standard privileges of a user. If it is omitted users get the default privileges `["Login", "Public Access"]`. The optional field for service users is `type` with values `User` or `ServiceUser` (default is `User`).

The customizing module is also able to automatically configure Microsoft 365 users for each OpenText Content Management user. To make this work, the Terraform variable for Office 365 / Microsoft 365 need to be configured. In particular `var.enable_o365` needs to be `true`. In the user settings `enable_o365` has to be set to `true` as well (or you use the variable `var.enable_o365` if the payload is in the `customization.tf` file). `m365_skus` defines a list of Microsoft 365 SKUs that should be assigned to the user. These are the technical SKU IDs that are documented by Microsoft: [Licensing Service Plans](https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference). Inside the `customizing.tf` file you also find a convenient map called `m365_skus` that map the SKU ID to readable names (such as "Microsoft 365 E3" or "Microsoft 365 E5"). The `enable_sap`, `enable_successfactors`, `enable_salesforce`, `enable_core_share` allow to automatically create + configure the users in connected SAP S/4HANA, SuccessFactors, Salesforce, and Core Share applications respectively.

=== "Terraform / HCL"

    ```terraform
    users = [
      {
        name                  = "adminton"
        password              = local.password
        firstname             = "Adam"
        lastname              = "Minton"
        email                 = "adminton@innovate.com"
        title                 = "Administrator"
        base_group            = "Administration"
        groups                = ["IT"]
        favorites             = ["workspace-a", "nickname-a"]
        security_clearance    = 50
        supplemental_markings = ["EUZONE"]
        privileges            = ["Login", "Public Access", "Content Manager", "Modify Users", "Modify Groups", "User Admin Rights", "Grant Discovery", "System Admin Rights"]
        enable_o365           = var.enable_o365
        m365_skus             = [var.m365_skus["Microsoft 365 E3"]]
        enable_sap            = var.enable_o365
        enable_successfactors = var.enable_o365
        enable_salesforce     = var.enable_o365
        enable_core_share     = var.enable_o365
        extra_attributes = [
            {
              name  = "oTExtraAttr0"
              value = "adminton${var.salesforce_username_suffix}"
            }
        ]
      },
      {
        name                  = "nwheeler"
        password              = local.password
        firstname             = "Nick"
        lastname              = "Wheeler"
        email                 = "nwheeler@innovate.com"
        title                 = "Sales Director"
        base_group            = "Sales"
        groups                = ["Manager", "Office365"]
        favorites             = ["workspace-b", "nickname-b"]
        security_clearance    = 95
        supplemental_markings = ["EU-GDPR-PD", "EUZONE"]
        privileges            = ["Login", "Public Access"]
        enable_o365           = var.enable_o365
        m365_skus             = [var.m365_skus["Microsoft 365 E5"]]
        enable_sap            = var.enable_o365
        enable_successfactors = var.enable_o365
        enable_salesforce     = var.enable_o365
        enable_core_share     = var.enable_o365
      }
    ]
    ```

=== "YAML"

    ```yaml
    users:
    - base_group: Administration
      email: adminton@innovate.com
      enable_o365: ${var.enable_o365}
      extra_attributes:
      - name: oTExtraAttr0
        value: adminton${var.salesforce_username_suffix}
      favorites:
      - workspace-a
      - nickname-a
      firstname: Adam
      groups:
      - IT
      lastname: Minton
      m365_skus:
      - ${var.m365_skus["Microsoft 365 E3"]}
      name: adminton
      password: ${local.password}
      privileges:
      - Login
      - Public Access
      - Content Manager
      - Modify Users
      - Modify Groups
      - User Admin Rights
      - Grant Discovery
      - System Admin Rights
      security_clearance: 50
      supplemental_markings:
      - EUZONE
      title: Administrator
    - base_group: Sales
      email: nwheeler@innovate.com
      enable_o365: ${var.enable_o365}
      enable_sap: ${var.enable_sap}
      enable_successfactors: ${var.enable_successfactors}
      enable_salesforce: ${var.enable_salesforce}
      enable_core_share: ${var.enable_core_share}
      favorites:
      - workspace-b
      - nickname-b
      firstname: Nick
      groups:
      - Manager
      - Office365
      lastname: Wheeler
      name: nwheeler
      password: ${local.password}
      privileges:
      - Login
      - Public Access
      security_clearance: 95
      supplemental_markings:
      - EU-GDPR-PD
      - EUZONE
      title: Sales Director
    ```

#### items

`items` and `itemsPost` are lists of OpenText Content Management items such as folders, shortcuts or URLs that should be created automatically but are not included in transports. All items are created in the `Enterprise Workspace` of OpenText Content Management or any subfolder.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, each item needs to have `name` and `type` values. The parent ID of the item can either be specified by a nick name (`parent_nickname`) or by the path in the Enterprise Workspace (`parent_path`). The value `parent_path` is a list of folder names starting from the root level in the Enterprise Workspaces. `parent_path = ["Administration", "WebReports"]` creates the item in the `WebReports` folder which is itself in the `Administration` top-level folder. The list `items` is processed at the beginning of the automation (before transports are applied) and `itemsPost` is applied at the end of the automation (after transports have been applied).

=== "Terraform / HCL"

    ```terraform
    items = [
        {
          enabled           = true
          parent_nickname   = "" # empty string = not set
          parent_path       = ["Administration", "WebReports"]
          name              = "Case Management"
          description       = "Case Management with eFiles and eCases"
          type              = var.otcs_item_types["Folder"]
          url               = "" # "" = not set
          original_nickname = 0  # 0 = not set
          original_path     = [] # [] = not set
        },
    ]

    itemsPost = [
      {
        parent_nickname = "" # empty string = not set
        parent_path = [
          "Administration", "Websites"
        ]
        name              = "OpenText Homepage"
        description       = "The OpenText web site"
        type              = var.otcs_item_types["URL"]
        url               = "https://www.opentext.com"
        original_nickname = 0  # 0 = not set
        original_path     = [] # [] = not set
      }
    ]

    ```

=== "YAML"

    ```yaml
    items:
    - description: Case Management with eFiles and eCases
      enabled: true
      name: Case Management
      original_nickname: 0
      original_path: []
      parent_nickname: ''
      parent_path:
      - Administration
      - WebReports
      type: ${var.otcs_item_types["Folder"]}
      url: ''
    itemsPost:
    - description: The OpenText web site
      enabled: true
      name: OpenText Homepage
      original_nickname: 0
      original_path: []
      parent_nickname: ''
      parent_path:
      - Administration
      - Websites
      type: ${var.otcs_item_types["URL"]}
      url: https://www.opentext.com

    ```

#### permissions

`permissions` and `permissionsPost` are both lists of Extended ECM items, each with a specific permission set that should be applied to the item.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, the item can be specified via a path (list of folder names in Enterprise workspace in top-down order), via a nickname, or via a volume. Permission values are listed as list strings in `[...]` for `owner_permissions`, `owner_group_permissions`, or `public_permissions`. They can be a combination of the following values: `see`, `see_contents`, `modify`, `edit_attributes`, `add_items`, `reserve`, `add_major_version`, `delete_versions`, `delete`, and `edit_permissions`. The `apply_to` specifies if the permissions should only be applied to the item itself (value 0) or only to sub-items (value 1) or the item _and_ its sub-items (value 2). The list specified by `permissions` is applied _before_ the transport packages are applied and `permissionsPost` is applied _after_ the transport packages have been processed.

=== "Terraform / HCL"

    ```terraform
    permissions = [
      {
        enabled = true
        path = ["...", "..."]
        volume = "..."   # identified by volume type ID
        nickname = "..." # an item with this nick name needs to exist
        owner_permissions = []
        owner_group_permissions = []
        public_permissions = ["see", "see_contents"]
        groups = [
            {
              name = "..."
              permissions = []
            }
        ]
        users = [
            {
              name = "..."
              permissions = []
            }
        ]
        apply_to = 2
      }
    ]
    ```

=== "YAML"

    ```yaml
    permissions:
    - apply_to: 2
      enabled: true
      groups:
      - name: '...'
        permissions: []
      nickname: '...'
      owner_group_permissions: []
      owner_permissions: []
      path:
      - '...'
      - '...'
      public_permissions:
      - see
      - see_contents
      users:
      - name: '...'
        permissions: []
      volume: '...'
    ```

#### renamings

`renamings` is a list of OpenText Content Management items (e.g. volume names) that are automatically renamed during deployment.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, you have to either provide the `nodeid` (only a few node IDs are really known upfront such as 2000 for the Enterprise Workspace) or a `volume` (type ID) with an optional `path` in that volume. Another alternative is to use a `nickname` to specify the node to be renamed. In case of volumes there's a list of known volume types defined at the beginning of the `customizing.tf` file with the variable `otcs_volumes`. You can also specify a description that will be used to update the description of the node / item.

=== "Terraform / HCL"

    ```terraform
    renamings = [
      {
        enabled     = true
        nodeid      = 2000
        name        = "Innovate"
        description = "Innovate's Enterprise Workspace"
      },
      {
        enabled     = true
        volume      = var.otcs_volumes["Content Server Document Templates"]
        name        = "Content Server Document Templates"
        description = "OpenText Content Management Workspace and Document Templates"
      }
    ]
    ```

=== "YAML"

    ```yaml
    renamings:
    - description: Innovate's Enterprise Workspace
      enabled: true
      name: Innovate
      nodeid: 2000
    - description: OpenText Content Management Workspace and Document Templates
      enabled: true
      name: Content Server Document Templates
      volume: ${var.otcs_volumes["Content Server Document Templates"]}
    ```

#### adminSettings

`adminSettings` and `adminSettingsPost` are lists of admin settings that are applied before the transport packages (`adminSettings`) or directly after the transport packages (`adminSettingsPost`) in the customizing process.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, each setting is defined by a `description`, the `filename` of an XML file that includes the actual OpenText Content Management admin settings that are applied automatically (using XML import / LLConfig). These files need to be stored inside the `setting/payload` sub-folder inside the terraform folder.

=== "Terraform / HCL"

    ```terraform
    adminSettings = [
      {
        description = "Apply minimum settings for Government Desktop (Inbox) that are required before users and groups are created."
        filename    = "GovernmentSettings-Inbox.xml", # this needs to happen before users and groups are created
      },
      {
        enabled     = var.enable_o365
        description = "These settings are removed by a side-effect during MS Teams automation. We need to re-enable them."
        filename    = "O365Settings.xml",
      }
    ]
    adminSettingsPost = [
      {
        description = "Apply Document Template settings that are dependent on Classification elements."
        filename    = "DocumentTemplatesSettings.xml"
      },
    ]
    ```

=== "YAML"

    ```yaml
    adminSettings:
    - description: Apply minimum settings for Government Desktop (Inbox) that are required
        before users and groups are created.
      filename: GovernmentSettings-Inbox.xml
    - description: These settings are removed by a side-effect during MS Teams automation.
        We need to re-enable them.
      enabled: ${var.enable_o365}
      filename: O365Settings.xml
    adminSettingsPost:
    - description: Apply Document Template settings that are dependent on Classification
        elements.
      filename: DocumentTemplatesSettings.xml
    ```

#### docgenSettings

`docgenSettings` allows you to set settings in OpenText Content Management Document Generation (OTPD - PowerDocs).

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, each document generation setting has a `name`, `value` and an optional `tenant`.

=== "Terraform / HCL"

    ```terraform
    docgenSettings = [
      {
        enabled = true
        name    = "LocalOtdsUrl"
        value   = "http://otds/otdsws"
      },
      {
        description = "Fix settings for local Kubernetes deployments"
        enabled     = true
        name        = "LocalApplicationServerUrlForContentManager"
        value       = "http://localhost:8080/c4ApplicationServer"
        tenant      = "Successfactors"
      }
    ]
    ```

=== "YAML"

    ```yaml
    docgenSettings:
    - enabled: true
      name: LocalApplicationServerUrlForContentManager
      tenant: Successfactors
      value: http://localhost:8080/c4ApplicationServer
    ```

#### externalSystems

`externalSystems` is a list of connections to external business applications such as SAP S/4HANA, Salesforce, or SuccessFactors. Some of the payload elements are common, some are specific for the type of the external system.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, the field `external_system_type` needs to have one of these values: `SAP`, `Salesforce`, `SuccessFactors`, `AppWorks Platform` or `Business Scenario Sample`. All other fields are dependent on the selection of the `external_system_type` value.

=== "Terraform / HCL"

    ```terraform
    externalSystems = [
      {
        enabled                  = var.enable_sap
        external_system_type     = "SAP"
        external_system_name     = "TM6"
        external_system_number   = var.sap_external_system_number
        description              = "SAP S/4HANA on-premise"
        as_url                   = "https://tmcerp1.eimdemo.biz:8443/sap/bc/srt/xip/otx/ecmlinkservice/100/ecmlinkspiservice/basicauthbinding"
        base_url                 = "https://tmcerp1.eimdemo.biz:8443"
        client                   = var.sap_external_system_client
        username                 = "demo"
        password                 = local.password
        certificate_file         = "/certificates/TM6.pse"
        certificate_password     = "topsecret"
        destination              = var.sap_external_system_destination
        archive_logical_name     = var.sap_archive_logical_name
        archive_certificate_file = "/certificates/${var.sap_archive_certificate_file}"
      },
      {
        enabled                = var.enable_salesforce
        external_system_type   = "Salesforce"
        external_system_name   = "SFDC-HTTP"
        description            = "Salesforce"
        as_url                 = "https://idea02dev-dev-ed.my.salesforce.com/services/Soap/c/48.0/"
        base_url               = "https://idea02dev-dev-ed.my.salesforce.com"
        username               = "idea02a2dev@opentext.com"
        password               = local.password
        oauth_client_id        = "..."
        oauth_client_secret    = "..."
        authorization_endpoint = "https://salesforce.com/services/oauth2/authorize"
        token_endpoint         = "https://salesforce.com/services/oauth2/token"
      },
      {
        enabled              = var.enable_successfactors
        external_system_type = "SuccessFactors"
        external_system_name = "SuccessFactors"
        description          = "SAP SuccessFactors"
        as_url               = "https://apisalesdemo8.successfactors.com/odata/v2"
        base_url             = "https://pmsalesdemo8.successfactors.com"
        username             = "sfadmin@SFPART035780"
        password             = local.password
        saml_url             = "https://salesdemo.successfactors.eu/idp/samlmetadata?company=SFSALES004711"
        otds_sp_endpoint     = "https://otds.xecm-cloud.com/otdsws"
        oauth_client_id      = "..."
        oauth_client_secret  = "..."
      }
    ]
    ```

=== "YAML"

    ```yaml
    externalSystems:
    - archive_logical_name: ${var.sap_archive_logical_name}
      archive_certificate_file: "/certificates/${var.sap_archive_certificate_file}"
      as_url: https://tmcerp1.eimdemo.biz:8443/sap/bc/srt/xip/otx/ecmlinkservice/100/ecmlinkspiservice/basicauthbinding
      base_url: https://tmcerp1.eimdemo.biz:8443
      certificate_file: /certificates/TM6.pse
      certificate_password: topsecret
      client: ${var.sap_external_system_client}
      description: SAP S/4HANA on-premise
      destination: ${var.sap_external_system_destination}
      enabled: ${var.enable_sap}
      external_system_name: TM6
      external_system_type: SAP
      password: ${local.password}
      username: demo
    - as_url: https://idea02dev-dev-ed.my.salesforce.com/services/Soap/c/48.0/
      authorization_endpoint: https://salesforce.com/services/oauth2/authorize
      base_url: https://idea02dev-dev-ed.my.salesforce.com
      description: Salesforce
      enabled: ${var.enable_salesforce}
      external_system_name: SFDC-HTTP
      external_system_type: Salesforce
      oauth_client_id: '...'
      oauth_client_secret: '...'
      password: ${local.password}
      token_endpoint: https://salesforce.com/services/oauth2/token
      username: idea02a2dev@opentext.com
    - as_url: https://apisalesdemo8.successfactors.com/odata/v2
      base_url: https://pmsalesdemo8.successfactors.com
      description: SAP SuccessFactors
      enabled: ${var.enable_successfactors}
      external_system_name: SuccessFactors
      external_system_type: SuccessFactors
      oauth_client_id: '...'
      oauth_client_secret: '...'
      otds_sp_endpoint: https://otds.xecm-cloud.com/otdsws
      password: ${local.password}
      saml_url: https://salesdemo.successfactors.eu/idp/samlmetadata?company=SFSALES004711
      username: sfadmin@SFPART035780
    ```

#### transportPackages

`transportPackages` is a list of transport packages that should be applied automatically. These packages need to be accessible via the provided URLs.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, the `name` must be the exact file name of the ZIP package. A value for `description` is optional.

=== "Terraform / HCL"

    ```terraform
    transportPackages = [
        {
          enabled     = true
          url         = "https://terrarium.blob.core.windows.net/transports/Terrarium-010-Categories.zip"
          name        = "Terrarium 010 Categories.zip"
          description = "Terrarium Category definitions"
        },
        {
          url         = "https://terrarium.blob.core.windows.net/transports/Terrarium-020-Classifications.zip"
          name        = "Terrarium 20 Classifications.zip"
          description = "Terrarium Classification definitions"
        },
        {
          enabled     = var.enable_sap
          url         = "${var.transporturl}/Terrarium-110-Business-Object-Types-SAP.zip"
          name        = "Terrarium 110 Business Object Types (SAP).zip"
          description = "Terrarium Business Object types for SAP"
          extractions = [
            {
              enabled = true
              xpath   = "/livelink/llnode[@objtype='889']"
            }
          ]
        },
        {
          enabled     = var.enable_o365
          url         = "${var.transporturl}/Terrarium-115-Scheduled-Processing-Microsoft.zip"
          name        = "Terrarium 115 Scheduled Processing (Microsoft).zip"
          description = "Terrarium Scheduled Processing Jobs for Microsoft Office 365"
          replacements = [
            {
              placeholder = "M365x62444544.onmicrosoft.com"
              value       = var.o365_domain
            },
            {
              placeholder = "M365x61936377.onmicrosoft.com"
              value       = var.o365_domain
            }
          ]
        }
    ]
    ```

=== "YAML"

    ```yaml
    transportPackages:
    - description: Terrarium Category definitions
      name: Terrarium 010 Categories.zip
      url: https://terrarium.blob.core.windows.net/transports/Terrarium-010-Categories.zip
    - description: Terrarium Classification definitions
      name: Terrarium 20 Classifications.zip
      url: https://terrarium.blob.core.windows.net/transports/Terrarium-020-Classifications.zip
    ```

#### contentTransportPackages

`contentTransportPackages` is a list of content transport packages that should be automatically applied. Content Transport Package typically are used to import documents into workspaces that are created before. These packages need to be accessible via the provided URLs.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

The `name` must be the exact file name of the ZIP package. Description is optional. Other than the `transportPackages` these transports are deployed **after** users and workspace instances have been processed. This allows to transport content into workspaces instances or use users inside these transport packages (e.g. owners, user attributes, etc.)

=== "Terraform / HCL"

    ```terraform
    contentTransportPackages = [
      {
        url         = "${var.transporturl}/Terrarium-300-Government-Content.zip"
        name        = "Terrarium 300 Government Content.zip"
        description = "Terrarium demo documents for Government scenario"
      },
      {
        url         = "${var.transporturl}/Terrarium-310-Enterprise-Asset-Management-Content.zip"
        name        = "Terrarium 310 Enterprise Asset Management Content.zip"
        description = "Terrarium demo documents for Enterprise Asset Management scenario"
      }
    ]
    ```

=== "YAML"

    ```yaml
    contentTransportPackages:
    - description: Terrarium demo documents for Government scenario
      name: Terrarium 300 Government Content.zip
      url: ${var.transporturl}/Terrarium-300-Government-Content.zip
    - description: Terrarium demo documents for Enterprise Asset Management scenario
      name: Terrarium 310 Enterprise Asset Management Content.zip
      url: ${var.transporturl}/Terrarium-310-Enterprise-Asset-Management-Content.zip
    ```

#### workspaceTemplates

`workspaceTemplates` is a list of workspace templates that should be modified before used by the workspace processing.
This payload allows to change the role memberships (adding new users or groups) and to add additional categories to workspace templates.

Each element is a dict with these keys:

- `enabled` (bool, optional, default = True)
- `type_name` (str, mandatory)
- `template_name` (str, mandatory)
- `members` (list, optional)
  - `role` (str, mandatory)
  - `users` (list, optional, default = [])
  - `groups` (list, optional, default = [])
- `categories` (list, optional)
  - `nickname` (str, optional) - the nickname of the category
  - `path` (list, optional) - the path to the category object in the category volume
  - `inheritance` (bool, optional) - should category inheritance be turned on on the workspace template node?
  - `apply_to_sub_items` (bool, optional) - should the category be inherited to existing sub-items?

#### workspaces

`workspaces` is a list of business workspaces instances that should be automatically created. Category, Roles, and Business Relationships can be provided.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, the `id` needs to be a unique value in the payload. It does not need to be something related to any of the actual OpenText Content Management workspace data. It is only used to establish relationship between different workspaces in the payload (using the list of related workspaces in `relationships`). **_Important_**: If the workspace type definition uses a pattern to generate the workspace name then the `name` in the payload should match the pattern in the workspace type definition. Otherwise incremental deployments of the payload may not find the existing workspaces and may try to recreate them resulting in an error. The `nickname` is the OpenText Content Management nickname that allows to refer to this item without knowing its technical ID.

The `relationships` are given as a list of related workspaces. The elements of the list can be:

- string or integer with logical workspace ID
- string with nickname of the related workspace
- list of dictionaries with `type` and `name` of the related workspace
- list of strings with the top-down path in the Enterprise volume

Business Object information can be provided with a `business_objects` list. Each list item defines the external system (see above), the business object type, and business object ID. This list is optional.

Roles and membership information is provided with the `members` list. Each list item defines membership for a single workspace role which is defined with `role`. Members can be defined by two lists: `users` and `groups`. In the first example below the role `Sales Representative` is populated with user `nwheeler` and with the groups `Sales` and `Management`.

Classification information is optional and can be provided separately for Records Management classifications and normal/regular classifications. Both types of classifications need to be provided as paths inside the respective classifications trees (top down). There can be only one Records Management classification but multiple regular classifications. That's why the element `classification_pathes` is a list of paths.

Category information is provided in a list of blocks. Each block includes the category `name`, `set` name (optional, can be empty if the attribute is not in a set), `attribute` name, and the attribute `value`. Multi-value attributes are a comma-separated list of items in square brackets. The example below shows a customer workspace and a contract workspace that are related to each other (the customer workspace has an attribute `Sales Organization` that has multiple values: 1000 and 2000). The contract workspace has a multi-line attribute set. For multi-line attribute sets the payload needs an additional `row` value that specifies the row number in the multi-line set (starting with 1 for the first row).

A third workspace in the example below is for `Material` - it has an additional field called `template_name` which is optional. It can be used if there are multiple templates for one workspace type. If it is not specified and the workspace type has multiple workspace templates the first template is automatically selected.

=== "Terraform / HCL"

    ```terraform
    workspaces = [
      {
        id          = "50031"
        name        = "Global Trade AG (50031)"
        nickname    = "ws_customer_global_trade"
        description = "Strategic customer in Germany"
        type_name   = "Customer"
        template_name = "Customer"
        business_objects = [
            {
              external_system = var.sap_external_system_name
              bo_type         = "KNA1"
              bo_id           = "0000050031"
            }
        ]
        members = [
            {
              role   = "Sales Representative"
              users  = ["nwheeler"]
              groups = ["Sales", "Management"]
            }
        ]
        classification_pathes = []
        rm_classification_path = [
            "RM Classifications",
            "Case Management",
            "Building Authorities",
            "01.Buildings",
            "01.Building applications",
            "02.Alteration and repair",
        ]
        categories = [
            {
              name      = "Customer"
              set       = ""
              attribute = "Customer Number"
              value     = "50031"
            },
            {
              name      = "Customer"
              set       = ""
              attribute = "Sales organisation"
              value     = ["1000", "2000"]
            },
            {
              name      = "Customer"
              set       = "Rating"
              attribute = "Institute"
              value     = "Dun & Bradstreet"
            }
        ]
        relationships = [
            "0040000019"
        ]
      },
      {
        id          = "0040000019"
        name        = "0040000019 - Global Trade AG"
        description = ""
        type_name   = "Sales Contract"
        members = [
            {
              role  = "Contract Manager"
              users = ["dfoxhoven"]
            }
        ]
        categories = [
            {
              name      = "Contract"
              set       = "Contract Data"
              attribute = "Function"
              value     = "Sales"
            },
            {
              name      = "Contract"
              set       = "Contract Data"
              attribute = "Contract Number"
              value     = "0040000019"
            },
            {
              name      = "Contract"
              set       = "Contract Line Items"
              row       = 1
              attribute = "Material Number"
              value     = "P-100"
            }
        ]
      },
      {
        id            = "R-9010"
        name          = "R-9010 - Notebook WebCam Model '16"
        description   = ""
        type_name     = "Material"
        template_name = "Material (Operating Supplies)"
        members = [
          {
            role  = "Master Data Management"
            users = ["kmurray"]
          }
        ]
        categories = [
          {
            name      = "Material"
            set       = ""
            attribute = "Material Number"
            value     = "R-9010"
          },
          {
            name      = "Material"
            set       = ""
            attribute = "Material Description"
            value     = "Notebook WebCam Model '16"
          }
        ]
      }
    ]
    ```

=== "YAML"

    ```yaml
    workspaces:
    - business_objects:
      - bo_id: '0000050031'
        bo_type: KNA1
        external_system: ${var.sap_external_system_name}
      categories:
      - attribute: Customer Number
        name: Customer
        set: ''
        value: '50031'
      - attribute: Sales organisation
        name: Customer
        set: ''
        value:
        - '1000'
        - '2000'
      - attribute: Institute
        name: Customer
        set: Rating
        value: Dun & Bradstreet
      classification_pathes: []
      description: Strategic customer in Germany
      id: '50031'
      members:
      - groups:
        - Sales
        - Management
        role: Sales Representative
        users:
        - nwheeler
      name: Global Trade AG (50031)
      relationships:
      - 0040000019
      rm_classification_path:
      - RM Classifications
      - Case Management
      - Building Authorities
      - 01.Buildings
      - 01.Building applications
      - 02.Alteration and repair
      template_name: Customer
      type_name: Customer
    - categories:
      - attribute: Function
        name: Contract
        set: Contract Data
        value: Sales
      - attribute: Contract Number
        name: Contract
        set: Contract Data
        value: 0040000019
      - attribute: Material Number
        name: Contract
        row: 1
        set: Contract Line Items
        value: P-100
      description: ''
      id: 0040000019
      members:
      - role: Contract Manager
        users:
        - dfoxhoven
      name: 0040000019 - Global Trade AG
      type_name: Sales Contract
    - categories:
      - attribute: Material Number
        name: Material
        set: ''
        value: R-9010
      - attribute: Material Description
        name: Material
        set: ''
        value: Notebook WebCam Model '16
      description: ''
      id: R-9010
      members:
      - role: Master Data Management
        users:
        - kmurray
      name: R-9010 - Notebook WebCam Model '16
      template_name: Material (Operating Supplies)
      type_name: Material

    ```

#### webReports

`webReports` and `webReportsPost` are two lists of OpenText Content Management web reports that should be automatically executed during deployment. Having two lists gives you the option to run some webReports after the business configuration and some others after demo content has been produced. These Web Reports have typically been deployed to OpenText Content Management system with the transport warehouse before. Each list item specifies one Web Report.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, the `nickname` is mandatory and defines the nickname of the Web Report to be executed. So you need to give each webReport you want to run a nickname before putting it in a transport package. The element `description` is optional. The `parameters` set defines parameter name and parameter value pairs. The corresponding Web Report in OpenText Content Management must have exactly these parameters defined.

=== "Terraform / HCL"

    ```terraform
    webReports = [
      {
        nickname    = "web_report_unset_xgov_doc_view"
        description = "Web Report to disable the Brava document view side bar"
        parameters = {
            "user_name" = "swang"
        }
      },
      {
        nickname    = "web_report_set_cust_sf"
        description = "Web Report to auto-configure OpenText Content Management for SuccessFactors Module Specific Settings"
      }
    ]

    webReportsPost = [
      {
        nickname    = "web_report_set_cust_sf"
        description = "Web Report to auto-configure OpenText Content Management for SuccessFactors Module Specific Settings"
      }
    ]
    ```

=== "YAML"

    ```yaml
    webReports:
    - description: Web Report to disable the Brava document view side bar
      nickname: web_report_unset_xgov_doc_view
      parameters:
        user_name: swang
    - description: Web Report to auto-configure OpenText Content Management for SuccessFactors Module
        Specific Settings
      nickname: web_report_set_cust_sf
    webReportsPost:
    - description: Web Report to auto-configure OpenText Content Management for SuccessFactors Module
        Specific Settings
      nickname: web_report_set_cust_sf
    ```

#### csApplications

`csApplications` is a list of Content Server Applications that should automatically be deployed.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, each element has a `name` for the application and optionally a `description`.

=== "Terraform / HCL"

    ```terraform
    csApplications = [
      {
        name        = "OTPOReports"
        description = "OpenText Physical Objects Reports"
      },
      {
        name        = "OTRMReports"
        description = "OpenText Records Management Reports"
      },
      {
        name        = "OTRMSecReports"
        description = "OpenText Security Clearance Reports"
      }
    ]
    ```

=== "YAML"

    ```yaml
    csApplications:
    - description: OpenText Physical Objects Reports
      name: OTPOReports
    - description: OpenText Records Management Reports
      name: OTRMReports
    - description: OpenText Security Clearance Reports
      name: OTRMSecReports
    ```

#### assignments

`assignments` is a list of assignments. Assignments are typically used for _Extended ECM for Government_.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

Each assignment assigns either a `workspace` or an OpenText Content Management item with a `nickname` to a defined list of `users` or `groups`. Assignments have a `subject` (title) and an optional `instruction` for the target users or groups.

=== "Terraform / HCL"

    ```terraform
    assignments = [
      {
        subject     = "Assignment on building extension M6P 1Y7-02-001-00001"
        instruction = "Please review this building extension"
        workspace   = "1063938"
        nickname    = ""
        users       = ["swang", "gbecker"]
        groups      = ["Case Management"]
      }
    ]
    ```

=== "YAML"

    ```yaml
    assignments:
    - groups:
      - Case Management
      instruction: Please review this building extension
      nickname: ''
      subject: Assignment on building extension M6P 1Y7-02-001-00001
      users:
      - swang
      - gbecker
      workspace: '1063938'

    ```

#### documentGenerators

`documentGenerators` defines a list of document generators that is based on the document template capabilities of OpenText Content Management. Each element is a dictionary with these fields:

- `enabled` switch to turn payload element on or off (the default is `true`)
- `workspace_type` is the name of the workspace type. It is a mandatory field.
- `template_path` is a mandatory list for folder names (top-down). It is a mandatory information.
- `classification_path` is a mandatory list of classification elements (top-down)
- `category_name` is the name of the category (optional)
- `attributes` is a list of dictionaries containing the attribute information. The dictionary has keys `name` and `value`.
- `workspace_folder_path` (list, optional, default = []) - default puts the document in the workspace root
- `exec_as_user` is optional and defines the name (login ID) of the user. If not provided the document is generated with admin credentials.

=== "Terraform / HCL"

    ```terraform
    documentGenerators = [
      {
        exec_as_user          = "pwilliams"
        workspace_type        = "Purchase Contract"
        workspace_folder_path = ["01 - Contract"]
        template_path         = ["Procurement", "Document Templates", "Purchasing Contract.docx"]
        classification_path   = ["Types", "Document Types", "Procurement", "Purchase Contract"]
        category_name         = "Contract Document"
        attributes = [
          {
            name  = "Status"
            value = "Approved"
          },
          {
            name  = "Legal Approval"
            value = "dfoxhoven"
          },
          {
            name  = "Legal Approval Date"
            value = "2023-05-11"
          },
          {
            name  = "Management Approval"
            value = "pwilliams"
          },
          {
            name  = "Management Approval Date"
            value = "2023-05-12"
          },
          {
            name  = "Official Document"
            value = true
          },
          {
            name  = "Language"
            value = "EN"
          },
          {
            name  = "File Type"
            value = "MS Word"
          },
        ]
      },
      ...
    ]
    ```

#### workflows

`workflows` is a list of workflow definitions. For each instance of the given workspace type, the Customizer starts the
workflow and then processes its steps in order.

The data is read from the payload key `workflows`, but the processing step is called `workflowInitiations`.
Therefore [payloadSections](#payloadsections) currently needs both entries: `workflows` (to load the data; the
Customizer logs an "Illegal payload section name" error for it, which can be ignored) and `workflowInitiations`
at the position where the workflows should be started (after the workspaces have been created):

```yaml
payloadSections:
- name: workflows
  enabled: true
# ... other sections ...
- name: workflowInitiations
  enabled: true
```

Each element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `workflow_nickname` (str, mandatory) - the nickname of the workflow map
- `workspace_type` (str, mandatory) - the name of the workspace type. For each instance of this workspace type a workflow is started.
- `workspace_folder_path` (list, optional) - path of the subfolder in the workspace that contains the documents the workflow is started with. All documents in this folder are attached to the workflow. If the path is not given, or does not exist in a workspace, the documents in the workspace root folder are used.
- `steps` (list, mandatory) - the workflow steps, processed in the given order. The first step must have the action `Initiate`. If a step fails, the remaining steps for this workspace are skipped.

Each step is a dictionary with these fields:

- `action` (str, mandatory) - `Initiate` starts the workflow. Any other value is passed as the action name to the current task of the started workflow (Content Server REST API, for example `formUpdate`). The user in `exec_as_user` must have the task in their inbox.
- `exec_as_user` (str, mandatory) - login name of the user that executes the step. The user must be defined in the [users](#users) section of the payload.
- `attributes` (list, optional) - workflow attribute values to set in this step. Each list element is a dictionary with the keys `name` (the attribute name in the workflow definition), `value` and an optional `type`. If `type` is `user`, then `value` is the login name of a user and is converted to the user ID.
- `title` (str, optional) - title of the workflow. Only used by the `Initiate` action.
- `comment` (str, optional) - comment of the workflow initiator. Only used by the `Initiate` action.
- `due_in_days` (int, optional) - number of days until the workflow is due (the due date is the current date plus this number of days). Only used by the `Initiate` action.

=== "Terraform / HCL"

    ```terraform
    workflows = [
      {
        enabled               = true
        workflow_nickname     = "wf_contract_approval_workflow"
        workspace_type        = "Purchase Contract"
        workspace_folder_path = ["01 - Contract"]
        steps = [
          {
            action       = "Initiate"
            exec_as_user = "pwilliams"
            title        = "Contract Approval Workflow for Purchase Contracts"
            comment      = "Workflow initiated by Terrarium automation"
            due_in_days  = 4
            attributes = [
              {
                name  = "Approver"
                value = "dfoxhoven"
                type  = "user"
              }
            ]
          }
        ]
      }
    ]
    ```

=== "YAML"

    ```yaml
    workflows:
    - enabled: true
      workflow_nickname: wf_contract_approval_workflow
      workspace_type: Purchase Contract
      workspace_folder_path:
      - 01 - Contract
      steps:
      - action: Initiate
        exec_as_user: pwilliams
        title: Contract Approval Workflow for Purchase Contracts
        comment: Workflow initiated by Terrarium automation
        due_in_days: 4
        attributes:
        - name: Approver
          value: dfoxhoven
          type: user
    ```

#### ontologies

`ontologies` is a list of ontologies (domains). An ontology describes relationships between workspace types (entities) and optionally synonyms and key aspects of these types. The workspace types must already exist, so list this section in `payloadSections` after the transport packages that create them.

The same workspace type can be part of multiple ontologies. In this case the synonyms, key aspects and predicates of all ontologies are merged, and relationships that already exist on the workspace type are not duplicated.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `name` (str, mandatory) - name of the ontology / domain
- `locale` (str, optional, default = system default metadata language of Content Management, or `en`) - language code used for synonyms, key aspects and predicates that are given as plain strings
- `entities` (list of dict, mandatory) - the workspace types that are part of the ontology. If empty, the ontology is skipped. Each element has these keys:
    - `name` (str, mandatory) - name of an existing workspace type
    - `description` (str, optional, default = empty) - free text description of the workspace type. Domains, synonyms and key aspects are appended to it for older versions of Content Management that have no native support for these values.
    - `synonyms` (list of str or dict, optional) - synonyms of the workspace type. Either a list of strings (assigned to `locale`) or a dictionary with language codes as keys and lists of strings as values.
    - `key_aspects` (list of str or dict, optional) - key aspects of the workspace type. Same format as `synonyms`.
- `relationships` (list of dict, mandatory) - the relationships between workspace types. If empty, the ontology is skipped. Each element has these keys:
    - `source_type` (str, mandatory) - name of the workspace type the relationship starts from. It should be listed in `entities`, as relationships are only processed for the entities of the ontology.
    - `target_type` (str, mandatory) - name of the existing workspace type the relationship points to
    - `direction` (str, optional, default = `child`) - type of the relationship. Either `child` or `parent`.
    - `predicates` (list of str or dict, optional) - phrases that describe the relationship (e.g. "has"). Each element is either a string (assigned to `locale`) or a dictionary with a language code as key and the phrase as value.

=== "Terraform / HCL"

    ```terraform
    ontologies = [
      {
        enabled = true
        name    = "Contract Management"
        locale  = "en"
        entities = [
          {
            name        = "Contract"
            description = "A legal agreement between two or more parties"
            synonyms    = ["Agreement"]
            key_aspects = ["Contract Value", "Expiration Date"]
          },
          {
            name     = "Vendor"
            synonyms = {
              en = ["Supplier"]
              de = ["Lieferant"]
            }
          }
        ]
        relationships = [
          {
            source_type = "Contract"
            target_type = "Vendor"
            direction   = "child"
            predicates  = ["is signed with", { de = "wird abgeschlossen mit" }]
          }
        ]
      }
    ]
    ```

=== "YAML"

    ```yaml
    ontologies:
    - enabled: true
      name: Contract Management
      locale: en
      entities:
      - name: Contract
        description: A legal agreement between two or more parties
        synonyms:
        - Agreement
        key_aspects:
        - Contract Value
        - Expiration Date
      - name: Vendor
        synonyms:
          en:
          - Supplier
          de:
          - Lieferant
      relationships:
      - source_type: Contract
        target_type: Vendor
        direction: child
        predicates:
        - is signed with
        - de: wird abgeschlossen mit
    ```

#### workspacePermissions

`workspacePermissions` is a list of permission settings that are applied to _all_ workspace instances of a given workspace type (or to a folder inside each of these workspaces). List it in `payloadSections` after the sections that create the workspaces.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `workspace_type` (str, mandatory) - name of the workspace type. The type must exist, otherwise the element is skipped with an error.
- `workspace_folder` (str, optional) - name of a folder inside each workspace. If specified, the permissions are applied to this folder instead of the workspace itself. Workspaces that do not contain such a folder are skipped. If omitted, the permissions are applied to the workspace itself.
- `regex` (bool, optional, default = `false`) - if `true`, `workspace_folder` is interpreted as a regular expression to find the folder in the workspace. Otherwise it is an exact folder name.
- `owner_permissions` (list of str, optional) - permissions of the item owner. Only applied if the key is present.
- `owner_group_permissions` (list of str, optional) - permissions of the owner group. Only applied if the key is present.
- `public_permissions` (list of str, optional) - permissions of the public access. Only applied if the key is present.
- `groups` (list of dict, optional) - permissions for specific groups. Each element has these keys:
    - `name` (str, mandatory) - name of the group
    - `permissions` (list of str, mandatory) - the permissions of the group
- `users` (list of dict, optional) - permissions for specific users. Each element has these keys:
    - `name` (str, mandatory) - login name of the user
    - `permissions` (list of str, mandatory) - the permissions of the user
- `apply_to` (int, optional, default = `2`) - specifies if the permissions are applied only to the item itself (value `0`), only to its sub-items (value `1`), to the item _and_ its sub-items (value `2`), or to the item and its immediate sub-items (value `3`)

Permission values are the same as for [permissions](#permissions): `see`, `see_contents`, `modify`, `edit_attributes`, `add_items`, `reserve`, `add_major_version`, `delete_versions`, `delete`, and `edit_permissions`.

=== "Terraform / HCL"

    ```terraform
    workspacePermissions = [
      {
        enabled                 = true
        workspace_type          = "Contract"
        workspace_folder        = "Documents"
        regex                   = false
        owner_permissions       = ["see", "see_contents", "modify"]
        owner_group_permissions = ["see", "see_contents"]
        public_permissions      = []
        groups = [
          {
            name        = "Contract Managers"
            permissions = ["see", "see_contents", "modify", "add_items"]
          }
        ]
        users = [
          {
            name        = "jdoe"
            permissions = ["see", "see_contents"]
          }
        ]
        apply_to = 2
      }
    ]
    ```

=== "YAML"

    ```yaml
    workspacePermissions:
    - enabled: true
      workspace_type: Contract
      workspace_folder: Documents
      regex: false
      owner_permissions:
      - see
      - see_contents
      - modify
      owner_group_permissions:
      - see
      - see_contents
      public_permissions: []
      groups:
      - name: Contract Managers
        permissions:
        - see
        - see_contents
        - modify
        - add_items
      users:
      - name: jdoe
        permissions:
        - see
        - see_contents
      apply_to: 2
    ```

#### categoryAssignments

`categoryAssignments` is a list of category assignments. Each element assigns a category to an existing item (identified by nickname or path) and sets attribute values of that category. If the category is already assigned to the item, only the attribute values are updated.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `item` (str or list of str, mandatory) - the item the category is assigned to. A string is interpreted as a nickname of the item. A list is interpreted as a path (list of folder names in top-down order) in the Enterprise Workspace or in the volume given by `volume`.
- `volume` (int, optional, default = Enterprise Workspace volume) - volume type ID used to resolve `item` if it is a path
- `category_item` (str or list of str, mandatory) - the category to assign. A string is interpreted as a nickname of the category. A list is interpreted as a path in the Categories Volume.
- `categories` (list of dict, mandatory) - the attribute values to set. All elements must refer to the same category, and the category name must match the name of the category given by `category_item`. Each element has these keys:
    - `name` (str, mandatory) - name of the category
    - `attribute` (str, mandatory) - name of the attribute
    - `value` (str, mandatory) - value of the attribute. For user attributes this is the login name of the user.
    - `set` (str, optional) - name of the set if the attribute is part of a set
    - `row` (int, optional) - row number for attributes in multi-row sets (mandatory for such attributes)
- `apply_to_sub_items` (bool, optional, default = `false`) - if `true`, the category is also assigned to all sub-items of the item
- `inheritance` (bool, optional, default = `false`) - if `true`, the category is inherited by items added to the item later (category inheritance)

=== "Terraform / HCL"

    ```terraform
    categoryAssignments = [
      {
        enabled            = true
        item               = ["Contracts", "Templates"]
        volume             = 141
        category_item      = ["Contract Management", "Contract Data"]
        apply_to_sub_items = false
        inheritance        = false
        categories = [
          {
            name      = "Contract Data"
            attribute = "Status"
            value     = "Draft"
          },
          {
            name      = "Contract Data"
            set       = "Parties"
            attribute = "Party Name"
            row       = 1
            value     = "Example Corp"
          }
        ]
      }
    ]
    ```

=== "YAML"

    ```yaml
    categoryAssignments:
    - enabled: true
      item:
      - Contracts
      - Templates
      volume: 141
      category_item:
      - Contract Management
      - Contract Data
      apply_to_sub_items: false
      inheritance: false
      categories:
      - name: Contract Data
        attribute: Status
        value: Draft
      - name: Contract Data
        set: Parties
        attribute: Party Name
        row: 1
        value: Example Corp
    ```

#### securityClearances

`securityClearances` creates security clearance levels in Content Management Records Management. The clearances are created by running a Web Report in Content Management.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `level` (str, mandatory) - security level value of the clearance (the level is passed as a string, e.g. `"10"`)
- `name` (str, mandatory) - name of the security clearance
- `description` (str, optional, default = empty) - description of the security clearance

=== "Terraform / HCL"

    ```terraform
    securityClearances = [
      {
        enabled     = true
        level       = "10"
        name        = "Confidential"
        description = "Confidential documents"
      }
    ]
    ```

=== "YAML"

    ```yaml
    securityClearances:
    - enabled: true
      level: '10'
      name: Confidential
      description: Confidential documents
    ```

#### supplementalMarkings

`supplementalMarkings` creates supplemental markings in Content Management Records Management. The markings are created by running a Web Report in Content Management.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `code` (str, mandatory) - code of the supplemental marking
- `description` (str, optional, default = empty) - description of the supplemental marking

=== "Terraform / HCL"

    ```terraform
    supplementalMarkings = [
      {
        enabled     = true
        code        = "EXPORT"
        description = "Export controlled"
      }
    ]
    ```

=== "YAML"

    ```yaml
    supplementalMarkings:
    - enabled: true
      code: EXPORT
      description: Export controlled
    ```

#### recordsManagementSettings

`recordsManagementSettings` imports Records Management and Physical Objects settings into Content Management from settings files. Unlike most other sections, this section is a single dictionary (not a list) and has no `enabled` switch.

The settings files must be available in the custom settings directory of the Customizer (setting `cust_settings_dir`); the file names are resolved relative to it. All keys are optional; a key that is missing or set to an empty string is skipped. The import steps run in the order listed below.

- `records_management_system_settings` (str, optional) - file name of the Records Management system settings to import
- `records_management_codes` (str, optional) - file name of the Records Management codes to import
- `records_management_rsis` (str, optional) - file name of the Records Management Retention Schedule Information (RSI) definitions to import
- `physical_objects_system_settings` (str, optional) - file name of the Physical Objects system settings to import
- `physical_objects_codes` (str, optional) - file name of the Physical Objects codes to import
- `physical_objects_locators` (str, optional) - file name of the Physical Objects locators to import
- `security_clearance_codes` (str, optional) - file name of the security clearance codes to import

=== "Terraform / HCL"

    ```terraform
    recordsManagementSettings = {
      records_management_system_settings = "rm_system_settings"
      records_management_codes          = "rm_codes"
      records_management_rsis           = "rm_rsis"
      physical_objects_system_settings  = "po_system_settings"
      physical_objects_codes            = "po_codes"
      physical_objects_locators         = "po_locators"
      security_clearance_codes          = "security_clearance_codes"
    }
    ```

=== "YAML"

    ```yaml
    recordsManagementSettings:
      records_management_system_settings: rm_system_settings
      records_management_codes: rm_codes
      records_management_rsis: rm_rsis
      physical_objects_system_settings: po_system_settings
      physical_objects_codes: po_codes
      physical_objects_locators: po_locators
      security_clearance_codes: security_clearance_codes
    ```

#### holds

`holds` creates Records Management holds in Content Management below the "Hold Maintenance" folder of the Records Management volume. If a hold with the same name already exists, it is skipped.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `name` (str, mandatory) - name of the hold
- `type` (str, mandatory) - type of the hold (e.g. `Legal`)
- `group` (str, optional) - name of a hold group (folder) below "Hold Maintenance" in which the hold is created. The group is created if it does not exist. Without a group the hold is created directly in "Hold Maintenance".
- `comment` (str, optional, default = empty) - comment for the hold
- `alternate_id` (str, optional) - alternate ID of the hold
- `date_applied` (str, optional) - date the hold is applied, format `YYYY-MM-DDTHH:mm:ss`.
- `date_to_remove` (str, optional) - date the hold is suspended / removed, format `YYYY-MM-DDTHH:mm:ss`

=== "Terraform / HCL"

    ```terraform
    holds = [
      {
        enabled        = true
        name           = "Contract Dispute 2025"
        type           = "Legal"
        group          = "Legal Holds"
        comment        = "Hold for documents related to the dispute"
        alternate_id   = "LH-2025-001"
        date_applied   = "2025-01-15T09:00:00"
        date_to_remove = "2026-01-15T09:00:00"
      }
    ]
    ```

=== "YAML"

    ```yaml
    holds:
    - enabled: true
      name: Contract Dispute 2025
      type: Legal
      group: Legal Holds
      comment: Hold for documents related to the dispute
      alternate_id: LH-2025-001
      date_applied: '2025-01-15T09:00:00'
      date_to_remove: '2026-01-15T09:00:00'
    ```

### Bulk Load Customizing Syntax

For mass loading and generation of workspaces, documents, items and classifications from external data sources the customizing allows to specify bulk datasources, bulk workspaces, bulk workspace relationships, bulk documents, bulk items, and bulk classifications. The data sources will be loaded in an internal table representation (we use Pandas Data Frames for this).

#### bulkDatasources

Before you can bulk load workspaces, workspace relationships, or documents you have to declare the used data sources. `bulkDatasources` is a list of datasources. Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`). First, a data source needs a `type`. Supported types are `excel` (Microsoft Excel workbooks), `servicenow` (ServiceNow REST API), `otmm` (OpenText Media Management REST API), `otcs` (OpenText Content Management REST API), `pht` (internal OpenText System for Product Master Data, REST API), `json` (JSON files), `csv` (comma-separated values), and `xml` (XML files, or whole directories / zip files of XML files). Based on the selected `type` data sources may have many specific fields to configure the specifics of the data source and define how to connect to the data source.

The following settings can be applied to all data source types:

- `cleansings` (dictionary, optional, default = {}) to clean the values in defined columns of the data set. Each list item is a dictionary with these keys:
  - `upper` (bool, optional, default = `false`) - convert complete string to upper case
  - `lower` (bool, optional, default = `false`) - convert complete string to lower case
  - `capitalize` (bool, optional, default = `false`) - capitalize first character of string
  - `title` (bool, optional, default = `false`) - capitalize first character of each word
  - `length` (int, optional, default = None)
  - `replacements` (dict, optional, default = `{}`) - the keys are regular expressions and the values are replacement values
- `columns_to_drop` (list, optional, default = `[]`) list of column names to remove from the data set (to black list those to delete)
- `columns_to_keep` (list, optional, default = `[]`) list of columns to keep in the data set and delete all others (to white list those to keep)
- `columns_to_add` (list, optional, default = `[]`) - each list item is a dictionary with these keys:
  - `source_column` (str, mandatory) - name of the column the base value for the new column is taken from
  - `name` (str, mandatory) - name of the new column
  - `reg_exp` (str, optional, default = None)
  - `prefix` (str, optional, default = "") - prefix to add to the new column value
  - `suffix` (str, optional, default = "") - suffix to add to the new column value
  - `length` (int, optional, default = None)
  - `group_chars` (str, optional, default = None)
  - `group_separator` (str, optional, default = `.`)
- `columns_to_add_list` (list, optional, default = []): add a new column with list values. Each payload item is a dictionary with these keys:
  - `source_columns` (str, mandatory) - names of the columns from which row values are taken from to create the list of string values
  - `name` (str, mandatory) - name of the new column
- `columns_to_add_concat` (list, optional, default = []): add a new column with concatenated values. Each payload item is a dictionary with these keys:
  - `source_columns` (str, mandatory) - names of the columns from which row values are taken from to create the list of string values
  - `name` (str, mandatory) - name of the new column
  - `concat_chars` (str, optional, default = "") - concatenation characters, e.g. "-" or "."
  - `lower` (bool, optional, default = False) - convert result to lower case
  - `upper` (bool, optional, default = False) - convert result to upper case
  - `capitalize` (bool, optional, default = False) - capitalize result
  - `title` (bool, optional, default = False) - convert result to title case
- `columns_to_add_table` (list, optional, default = []): add a new column with table values. Each payload item is a dictionary with these keys:
  - `source_columns` (str, mandatory) - names of the columns from which row values are taken from to create a list of dictionary values. It is expected that the source columns already have list items or are strings with delimiter-separated values.
  - `name` (str, mandatory) - name of the new column
  - `list_splitter` (str, optional, default = `,`) Defines the delimiter for splitting strings from the source columns into a list.
- `conditions` (list, optional, default = []) - each list item is a dict with these keys:
  - `field` (str, mandatory)
  - `value` (str | bool | list, optional, default = None)
  - `equal` (bool, optional): if `true` test for equality (this is the default), if `false` test for non-equality
- `explosions` (list, optional, default = []) - each list item is a dict with these keys:
  - `explode_fields` (str | list, mandatory)
  - `flatten_fields` (list, optional, default = `[]`)
  - `split_string_to_list` (bool, optional, default = False)
  - `list_splitter` (str, optional) - defines the delimiters for splitting strings in a list. Always set it if `split_string_to_list` is `true`.
- `name_column` (str, optional, default = None) - name of the column in the data source that determines the bulk item name
- `synonyms_column` (str, optional, default = None)

CSV File specific settings:

- `csv_delimiter` (str, optional) - value delimiter in the file - default is a comma
- `csv_header_index` (int, optional) - if the file has a header line this parameter specifies the index (0 = first line, this is the default)
- `csv_column_names` (list, optional) - if the file has no header line the column name can be specified as a list of strings
- `csv_use_columns` (list, optional) - this list can either include integers (index of columns to keep), strings (names of columns to keep), or a list of boolean values (True = column is kept, False = column is dropped)

OpenText Content Management / Content Server specific settings (fields):

- `otcs_hostname` (str, mandatory)
- `otcs_protocol` (str, optional, default = `https`)
- `otcs_port` (str, optional, default = `443`)
- `otcs_basepath` (str, optional, default = `/cs/cs`)
- `otcs_username` (str, mandatory)
- `otcs_password` (str, mandatory)
- `otcs_thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `otcs_download_dir` (str, optional, default = `/data/contentserver`)
- `otcs_root_node_ids` (int | list[int], mandatory)
- `otcs_include_workspaces` (bool, optional, default = True) - if workspace rows should be created in the data frame
- `otcs_include_items` (bool, optional, default = True) - if item rows should be created in the data frame
- `otcs_include_workspace_metadata` (bool, optional, default = True) - if metadata columns for workspaces should be created in the data frame
- `otcs_include_item_metadata` (bool, optional, default = True) - if metadata columns for items should be created in the data frame
- `otcs_filter_workspace_depth` (int, optional, default = 0) - 0 = workspaces are located immediately below given root node
- `otcs_filter_workspace_subtypes` (list, optional, default = `[]`) - 0 = folder subtype
- `otcs_filter_workspace_category` (str, optional, default = None) - defines the category the workspace needs to have to pass the filter
- `otcs_filter_workspace_attributes` (dict | list, optional, default = None)
  - `set` (str, optional, default = None) - name of the attribute set
  - `row` (int, optional, default = None) - row number (starting with 1) - only required for multi-value sets
  - `attribute` (str, mandatory) - name of the attribute
  - `value` (str, mandatory) - value the attribute should have to pass the filter
- `otcs_filter_item_depth` (int, optional, default = None) - depth of the document under the given root
- `otcs_filter_item_subtypes` (list, optional, default = `[]`) - 0 = folder subtype, 144 = document subtype
- `otcs_filter_item_category` (str, optional, default = None) - defines the category that the item needs to have to pass the filter
- `otcs_filter_item_attributes` (dict | list, optional, default = None)
  - `set` (str, optional, default = None) - name of the attribute set
  - `row` (int, optional, default = None) - row number (starting with 1) - only required for multi-value sets
  - `attribute` (str, mandatory) - name of the attribute
  - `value` (str, mandatory) - value the attribute should have to pass the filter
- `otcs_filter_item_in_workspace` (bool, optional, default = True) - defines whether or not items in workspace should also be filtered
- `otcs_exclude_node_ids` (list, optional, default = None) - list of Content Server IDs to exclude from loading / traversing
- `otcs_download_documents` (bool, optional, default = True) - defines whether or not documents should actually be downloaded
- `otcs_skip_existing_downloads` (bool, optional, default = True) - defines whether or not documents downloaded before and still exist in the filesystem should be downloaded once more
- `extract_zip` (bool, optional, default = False) - defines whether or not zip files should be uncompressed and its content should be uploaded instead
- `otcs_use_numeric_category_identifier` (bool, optional, default = True) - defines whether or not category IDs should be used in data frame columns. If `False` then a normalized category name will be used instead

ServiceNow specific settings (fields):

- `sn_base_url` (str, mandatory) - ServiceNow base URL
- `sn_auth_type` (str, optional, default = `basic`) - authentication type of ServiceNow
- `sn_username` (str, optional, default = "") - user name used with ServiceNow
- `sn_password` (str, optional, default = "") - password of the provided user
- `sn_client_id` (str, optional, default = None) - client ID of ServiceNow
- `sn_client_secret` (str, optional, default = None) - client secret of ServiceNow
- `sn_table_name` (str, optional, default = `u_kb_template_technical_article_public`) - name of the table used for the Knowledge Base Articles
- `sn_queries` (list, mandatory) - list of queries to retrieve the Knowledge base articles
  - `sn_table_name` (str, mandatory) - name of the ServiceNow database table for the query
  - `sn_query` (str, mandatory) - query string
- `sn_thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `sn_download_dir` (str, optional, default = `/data/knowledgebase`) - the directory in the file system where attachments from ServiceNow should be stored for further processing
- `sn_skip_existing_downloads` (bool, optional, default = True) - whether or not attachments that have been downloaded before should be reused

OpenText Media management specific settings (fields):

- `otmm_username` (str, optional, default = "") - name of the user for the asset retrieval
- `otmm_password` (str, optional, default = "") - password of the given user
- `otmm_client_id` (str, optional, default = None) - client ID for authentication
- `otmm_client_secret` (str, optional, default = None) - client secret for authentication
- `otmm_thread_number` (int, optional, default = BULK_THREAD_NUMBER) - number of parallel running threads
- `otmm_download_dir` (str, optional, default = `/data/mediaassets`) - directory in the customizer pod to temporarily store the asset files
- `otmm_business_unit_exclusions` (list, optional, default = `[]`) - black list for Business Units to exclude
- `otmm_business_unit_inclusions` (list, optional, default = `[]`) - white list for Business Units to include
- `otmm_product_exclusions` (list, optional, default = `[]`) - black list of products to exclude
- `otmm_product_inclusions` (list, optional, default = `[]`) - white list of products to include

OpenText Product Hierarchy Tracker (PHT) specific settings (fields):

- `pht_base_url` (str, mandatory) - PHT base URL
- `pht_username` (str, optional, default = "") - name of the user for the data retrieval
- `pht_password` (str, optional, default = "") - password of the given user
- `pht_business_unit_exclusions` (list, optional, default = `[]`) - black list for Business Units to exclude
- `pht_business_unit_inclusions` (list, optional, default = `[]`) - white list for Business Units to include
- `pht_product_exclusions` (list, optional, default = `[]`) - black list of products to exclude
- `pht_product_inclusions` (list, optional, default = `[]`) - white list of products to include
- `pht_product_category_exclusions` (list, optional, default = [])
- `pht_product_category_inclusions` (list, optional, default = [])
- `pht_product_status_exclusions` (list, optional, default = [])
- `pht_product_status_inclusions` (list, optional, default = [])
- `pht_product_attributes` (list, optional, default = []) - a list of attribute names that should be extracted and added as columns to the data frame

Filesystem specific settings (fields):

- `root_folders` (list, mandatory) - a list of paths to root folders that are traversed to load the data frame. The dataframe will have the following columns: `filename`, `size`, `path`, `relative_path`, `download_dir` and columns for each path part that are numbered like this: `level <n>`.

This is an example for a bulkDatasources definition:

=== "Terraform / HCL"

    ```terraform
    bulkDatasources = [
      {
        enabled     = true
        name        = "ntsb"
        description = "NTSB Data Source from https://www.ntsb.gov"
        type        = "json"
        json_files  = ["/datasources/ntsb-2024-01.json", "/datasources/ntsb-2024-02.json", "/datasources/ntsb-1962-2023.json"]

        # columns to keep. If empty we keep all columns
        columns_to_keep = [
          "cm_mkey",
          "cm_ntsbNum",
          "...",
        ]
        # columns to drop. If empty we drop no columns
        columns_to_drop = []
        explosions = [
          {
            explode_fields = "cm_vehicles"
            flatten_fields = ["make", "model", "operatorName"]
          }
        ]
        conditions= [
            {
                "field": "cm_vehicles_operatorName",
                "value": [
                  "AIR CANADA",
                  "AIR CHINA",
                  "..."
                ],
                "regex": false,
            },
        ]

        cleansings = {
          "airportName": {
            "upper": true
            "replacements" : {
              "-": " ",  # replace hyphen with space
              "/": " ",  # replace slash with space
              " AIRPORT$": "",  # remove " AIRPORT" at the end of names
              " AIRPOR$": "",  # remove " AIRPOR" at the end of names
              " ARPT$": "",  # remove " ARPT" at the end of names
              " AIRP$": "",  # remove " AIRP" at the end of names
              " A$": "",  # remove " A" at the end of names (abbreviation for Airport)
            }
          }
        }
      }
    ]
    ```

#### bulkWorkspaces

To bulk load workspaces you can define a payload section `bulkWorkspaces` which can produce a large number of workspaces based on placeholders that are filled with data from a defined data source. Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`). First, a data source needs a `data_source` that specifies the name of a data source in the `bulkDatasources` payload section.

These are the settings in a single bulk workspace list element:

- `enabled` (bool, optional, default = `true`)
- `type_name` (str, mandatory) - type of the workspace
- `data_source` (str, mandatory) - name of a data source item defined in the `bulkDatasources` section.
- `force_reload` (bool, optional, default = `true`) - enforce a reload of the data source, e.g. useful if data source has been modified before by column operations or explosions
- `copy_data_source` (bool, optional, default = `false`) - to avoid side effects for repeated usage of the data source
- `operations` (list, optional, default = `["create"]`) - list of operations to apply for workspaces: `create`, `update`, `delete`, `recreate` (any combination of these). "recreate" = delete existing + create new
- `update_operations` (list, optional, default = `["name", "description", "categories", "nickname"]`) - list of update operations to apply for workspaces if operation `update` is selected.
- `explosions` (list, optional, default = `[]`) - each list item is a dict with these keys:
  - `explode_fields` (str | list, mandatory)
  - `flatten_fields` (list, optional, default = `[]`)
  - `split_string_to_list` (bool, optional, default = `false`)
  - `list_splitter` (str, optional, default = `,`) - defines the delimiters for splitting strings in a list.
- `unique` (list, optional, default = `[]`) - list of fields (columns) that should be unique -> deduplication
- `sort` (list, optional, default = `[]`) - list of fields to sort the data frame by
- `name` (str, mandatory) - name of the workspace - can include placeholder surrounded by {...}
- `name_alt` (str, optional, default = None) - alternative name of the workspace (used if `name` is evaluated to empty string)
- `description` (str, optional, default = "") - can include placeholder surrounded by {...}
- `description_alt` (str, optional, default = None) - alternative description of the workspace (used if `description` is evaluated to empty string)
- `template_name` (str, optional, default = take first template)
- `categories` (list, optional, default = `[]`) - each list item is a dictionary that may have these keys:
  - `name` (str, mandatory)
  - `set` (str, default = "")
  - `row` (int, optional)
  - `attribute` (str, mandatory)
  - `value` (str, optional if value_field is specified, default = None)
  - `value_field` (str, optional if value is specified, default = None) - can include placeholder surrounded by {...}
  - `value_type` (str, optional, default = `string`) - possible values: `string`, `datetime`, `list` and `table`. If `list` is selected, then string with delimiter-separated values will be converted to a list.
  - `attribute_mapping` (dict, optional, default = None) - only relevant for value_type = "table" - defines a mapping from the data frame column names to the category attribute names
  - `value_mapping` (dict, optional, default = None) - dictionary keys are the original values and dictionary values are the mapped values. This makes most sense for values with a limited / fixed domain of possible values
  - `list_splitter` (str, optional, default = `;,`) - only relevant for value_type `list`. Defines the delimiter for splitting strings in a list.
  - `lookup_data_source` (str, optional, default = None)
  - `lookup_data_failure_drop` (bool, optional, default = false) - should we clear / drop values that cannot be looked up?
  - `is_key` (bool, optional, default = false) - find workspace if name matching does not work (e.g. workspace name has changed in the data source since last run). For this we expect a `key` value to be defined in the bulk workspace and one of the category / attribute item to be marked with `is_key = true`.
- `external_create_date` (str, optional, default = "")
- `external_modify_date` (str, optional, default = "")
- `key` (str, optional, default = None) - lookup value for workspaces other than the name. Works in combination with `is_key` in the `categories` payload.
- `replacements` (dict, optional, default = `{}`) - Each dictionary item has the field name as the dictionary key and a list of regular expressions as dictionary value
- `nickname` (str, optional, default = None) - nickname of the workspace - can include placeholder surrounded by {...}
- `nickname_alt` (str, optional, default = None) - alternative nickname of the workspace (used if `nickname` is evaluated to empty string)
- `conditions` (list, optional, default = `[]`) - each list item is a dictionary that may have these keys:
  - `field` (str, mandatory)
  - `value` (str | bool | list, optional, default = None) - if no value is specified only the existence of the field is tested
  - `equal` (bool, optional): if True test for equality (this is the default), if False test for non-equality
- `aviator_metadata` (bool, optional, default = `false`) - Send request to FEME to embed the metadata for the workspace. Action will be performed after updates and creations.

This is an example for a bulkWorkspaces definitions:

=== "Terraform / HCL"

    ```terraform
    bulkWorkspaces = [
      {
        data_source    = "ntsb"
        name           = "{airportName} ({airportId})"
        nickname       = "ws_location_{airportName}_{airportId}"
        description    = ""
        type_name      = "Location"
        template_name  = "Location"
        conditions     = [
          {
            field = "{airportName}"
          },
          {
            field = "{airportId}"
          }
        ]
        unique       = ["airportName", "airportId"]
        sort         = ["airportName"]  # sorting may help to avoid name clashes between threads
        replacements = {} # no "local" replacements
      },
      {
        data_source    = "ntsb"
        name           = "{cm_vehicles.make}"
        nickname       = "ws_manufacturer_{cm_vehicles.make}"
        description    = ""
        type_name      = "Manufacturer"
        template_name  = "Manufacturer"
        conditions     = [
          {
            field = "{cm_mode}"
            value = "Aviation"
          },
          {
            field = "{cm_vehicles.make}"
          }
        ]
        unique = ["cm_vehicles_make"]
        sort   = ["cm_vehicles_make"]  # sorting may help to avoid name clashes between threads
        replacements = {} # no "local" replacements
      },
      {
        data_source    = "ntsb"
        name           = "{cm_vehicles.operatorName}"
        nickname       = "ws_operator_{cm_vehicles.operatorName}"
        description    = ""
        type_name      = "Operator"
        template_name  = "Operator"
        conditions     = [
          {
            field = "{cm_vehicles.operatorName}"
          }
        ]
        unique = ["cm_vehicles_operatorName"] # we must have an underscore here as this is a generated top-level field
        sort   = ["cm_vehicles_operatorName"] # sorting may help with avoiding name clashes between threads
        replacements = {} # no "local" replacements
      },
      {
        data_source    = "ntsb"
        name           = "{cm_ntsbNum}"
        nickname       = "ws_incident_{cm_ntsbNum}"
        description    = ""
        type_name      = "Incident"
        template_name  = "Incident"
        unique         = ["cm_ntsbNum"] # the explosion may generate multiple lines for one NTSB number
        replacements   = {} # no "local" replacements
        categories = [
          {
            name        = "Incident"
            set         = ""
            attribute   = "Key"
            value_field = "{cm_mkey}"
          },
          {
            name        = "Incident"
            set         = ""
            attribute   = "Status"
            value_field = "{cm_completionStatus}"
          },
          {
            name        = "Incident"
            set         = ""
            attribute   = "Has Safety Recommendation"
            value_field = "{cm_hasSafetyRec}"
          },
          {
            name        = "Incident"
            set         = ""
            attribute   = "Highest Injury Level"
            value_field = "{cm_highestInjury}"
          },
          ...
        ]
      },
    ]
    ```

#### bulkWorkspaceRelationships

To bulk load workspace relationships you can define a payload section `bulkWorkspaceRelationships` which can produce a large number of workspace relationships based on placeholders that are filled with data from a defined data source.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, a bulk workspace relationship needs a `data_source` that specifies the name of a data source in the `bulkDatasources` payload section. Then the _from_ workspace name is either defined by `from_workspace` (which is the nickname) and the _to_ workspace nickname is defined by `to_workspace`. Alternatively, the _from_ and _to_ workspaces can be determined by the combination of the type (`from_workspace_type`, `to_workspace_type`) and the name (`from_workspace_name` and `to_workspace_name`) of the workspaces. The `type` defines if the _from_ workspace is the child or the parent in the relationship.

These are all the settings in a single bulk workspace relationship list element:

- `enabled` (bool, optional, default = true)
- `from_workspace` (str, mandatory) - nickname of the workspace on the _from_ side.
- `from_workspace_type` (str, optional, default = None) - type name of the workspace on the _from_ side.
- `from_workspace_name` (str, optional, default = None) - name of the workspace on the _from_ side.
- `from_workspace_data_source` (str, optional, default = None)
- `from_sub_workspace_name` (str, optional, default = None) - if the related workspace is a sub-workspace
- `from_sub_workspace_path` (list, optional, default = None) - the folder path under the main workspace where the sub-workspaces are located
- `from_workspace_lookup_error` (bool, optional, default = True) - whether or not an error should be logged if a relationship endpoint cannot be looked up
- `to_workspace` (str, mandatory) - nickname of the workspace on the _to_ side.
- `to_workspace_type` (str, optional, default = None) - type name of the workspace on the _to_ side.
- `to_workspace_name` (str, optional, default = None) - name of the workspace on the _to_ side.
- `to_workspace_data_source` (str, optional, default = None)
- `to_sub_workspace_name` (str, optional, default = None) - if the related workspace is a sub-workspace
- `to_sub_workspace_path` (list, optional, default = None) - the folder path under the main workspace where the sub-workspaces are located
- `to_workspace_lookup_error` (bool, optional, default = True) - whether or not an error should be logged if a relationship endpoint cannot be looked up
- `type` (str, optional, default = `child`) - type of the relationship (defines if the _from_ workspace is the parent or the child)
- `data_source` (str, mandatory)
- `force_reload` (bool, optional, default = true) - enforce a reload of the data source, e.g. useful if data source has been modified before by column operations or explosions
- `copy_data_source` (bool, optional, default = false) - to avoid side effects for repeated usage of the data source
- `explosions` (list, optional, default = `[]`) - each list item is a dict with these keys:
  - `explode_fields` (str | list, mandatory)
  - `flatten_fields` (list, optional, default = `[]`)
  - `split_string_to_list` (bool, optional, default = `false`)
  - `list_splitter` (str, optional, default = `,`) - defines the delimiters for splitting strings in a list.
- `unique` (list, optional, default = [])
- `sort` (list, optional, default = [])
- `thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `replacements` (list, optional, default = None)
- `conditions` (list, optional, default = None)
  - `field` (str, mandatory)
  - `value` (str | bool | list, optional, default = None)
  - `equal` (bool, optional): if `true` then test for equality (this is the default), if `false` test for non-equality

This is an example for bulkWorkspaceRelationships definitions:

=== "Terraform / HCL"

    ```terraform
    bulkWorkspaceRelationships = [
      {
        # Relationship between Incidents and Airports:
        data_source    = "ntsb"
        from_workspace = "ws_incident_{cm_ntsbNum}"
        to_workspace   = "ws_location_{airportName}_{airportId}"
        type           = "parent"
        conditions     = [
          {
            field = "{airportName}"
          },
          {
            field = "{airportId}"
          }
        ]
        unique = ["cm_ntsbNum", "airportName", "airportId"] # this is important to remove duplicates produced by explosions
        sort = ["cm_ntsbNum"] # sorting may help to avoid name clashes between threads
        replacements   = {} # no "local" replacements
      },
      {
        # Relationship between Incidents and Manufacturers:
        data_source    = "ntsb"
        from_workspace = "ws_incident_{cm_ntsbNum}"
        to_workspace   = "ws_manufacturer_{cm_vehicles.make}"
        type           = "parent"
        conditions = [
          {
            field = "{cm_vehicles.make}"
          }
        ]
        unique = ["cm_ntsbNum", "cm_vehicles_make"] # need to use the flattened field here
        sort = ["cm_ntsbNum"] # sorting may help to avoid name clashes between threads
        replacements = {} # no "local" replacements
      },
      {
        # Relationship between Incidents and Airlines:
        data_source    = "ntsb"
        from_workspace = "ws_incident_{cm_ntsbNum}"
        to_workspace   = "ws_operator_{cm_vehicles.operatorName}"
        type           = "parent"
        conditions     = [
          {
            field = "{cm_vehicles.operatorName}" # ensure we only process rows that have operatorName field
          }
        ]
        unique = ["cm_ntsbNum", "cm_vehicles_operatorName"] # need to use the flattened field here
        sort = ["cm_ntsbNum"] # sorting may help to avoid name clashes between threads
        replacements = {} # no "local" replacements
      }
    ]
    ```

#### bulkDocuments

To bulk load documents you can define a payload section `bulkDocuments` which can upload a large number of documents based on placeholders that are filled with data from a defined data source. Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`). First, a bulk document needs a `data_source` that specifies the name of a data source in the `bulkDatasources` payload section.

These are all the settings in a single bulk document list element:

- `enabled` (bool, optional, default = true)
- `data_source` (str, mandatory)
- `force_reload` (bool, optional, default = true) - enforce a reload of the data source, e.g. useful if data source has been modified before by column operations or explosions
- `copy_data_source` (bool, optional, default = false) - to avoid side effects for repeated usage of the data source
- `explosions` (list of dicts, optional, default = [])
  - `explode_fields` (str | list, mandatory)
  - `flatten_fields` (list, optional, default = [])
  - `split_string_to_list` (bool, optional, default = false)
  - `list_splitter` (str, optional) - defines the delimiters for splitting strings in a list. Always set it if `split_string_to_list` is `true`.
- `unique` (list, optional, default = []) - list of fields (columns) that should be unique -> deduplication
- `sort` (list, optional, default = []) - list of fields to sort the data frame by
- `operations` (list, optional, default = ["create"]) - possible values: `create`, `update`, `delete`, `recreate`
- `update_operations` (list, optional, default = `["name", "description", "categories", "version"]`) - list of update operations to apply for documents if `update` is included in operations (see above).
- `name` (str, mandatory) - can include placeholder surrounded by {...}
- `name_alt` (str, optional, default = None) - can include placeholder surrounded by {...}
- `name_regex` (str, optional, default = r"") - regex replacement for document names. The pattern and replacement are separated by pipe character |
- `description` (str, optional, default = None) - can include placeholder surrounded by {...}
- `download_name` (str, optional, default = name) - - can include placeholder surrounded by {...}
- `download_name_wildcards` (bool, optional, default = False) - defines if the download name includes wildcards, e.g. "*.pdf"
- `nickname` (str, optional, default = None) - can include placeholder surrounded by {...}
- `download_url` (str, optional, default = None)
- `download_url_alt` (str, optional, default = None)
- `download_dir` (str, optional, default = BULK_DOCUMENT_PATH)
- `delete_download` (bool, optional, default = `true`)
- `file_extension` (str, optional, default = "")
- `file_extension_alt` (str, optional, default = `html`)
- `mime_type` (str, optional, default = `application/pdf`)
- `mime_type_alt` (str, optional, default = `text/html`)
- `categories` (list, optional, default = `[]`)
  - `name` (str, mandatory)
  - `set` (str, default = "")
  - `row` (int, optional)
  - `attribute` (str, mandatory)
  - `value` (str, optional if value_field is specified, default = None)
  - `value_field` (str, optional if value is specified, default = None) - can include placeholder surrounded by {...}
  - `value_type` (str, optional, default = `string`) - possible values: `string`, `datetime`, `list`, and `table`. If list then string with comma-separated values will be converted to a list.
  - `attribute_mapping` (dict, optional, default = None) - only relevant for value type `table` - defines a mapping from the data frame column names to the category attribute names
  - `list_splitter` (str, optional, default = `;,`) - only relevant for value type `list`. Defines the delimiter for splitting strings in a list.
  - `lookup_data_source` (str, optional, default = None)
  - `lookup_data_failure_drop` (bool, optional, default = false) - should we clear / drop values that cannot be looked up?
  - `is_key` (bool, optional, default = false) - find document is old name. For this we expect a `key` value to be defined for the bulk document and one of the category / attribute item to be marked with `is_key = true`.
- `thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `external_create_date` (str, optional, default = "")
- `external_modify_date` (str, optional, default = "")
- `key` (str, optional, default = None) - lookup key for documents other than the name
- `download_wait_time` (int, optional, default = 30)
- `download_retries` (int, optional, default = 2)
- `replacements` (list, optional, default = `[]`)
- `conditions` (list, optional, default = `[]`) - all conditions must evaluate to true
  - `field` (str, mandatory)
  - `value` (str | bool | list, optional, default = None)
  - `equal` (bool, optional): if `true` test for equality (this is the default), if `false` test for non-equality
- `workspaces` (list, optional, default = `[]`) - the workspaces the document should be uploaded to
  - `workspace_name` (str, mandatory)
  - `conditions` (list, optional, default = `[]`)
    - `field` (str, mandatory)
    - `value` (str | bool | list, optional, default = None)
    - `equal` (bool, optional): if `true` test for equality (this is the default), if `false` test for non-equality
  - `workspace_type` (str, mandatory)
  - `data_source` (str, optional, default = None)
  - `workspace_folder` (str, optional, default = "")
  - `workspace_path` (list, optional, default = `[]`)
  - `sub_workspace_type` (str, optional, default = "")
  - `sub_workspace_name` (str, optional, default = "")
  - `sub_workspace_template` (str, optional, default = "")
  - `sub_workspace_folder` (str, optional, default = "")
  - `sub_workspace_path` (list, optional, default = `[]`)

This is an example for bulkDocuments definitions:

=== "Terraform / HCL"

    ```terraform
    bulkDocuments = [
      {
        data_source             = "ntsb"
        download_url            = "https://data.ntsb.gov/carol-repgen/api/Aviation/ReportMain/GenerateNewestReport/{cm_mkey}/pdf"
        download_dir            = "/data/ntsb/incident-reports/"
        name                    = "{cm_ntsbNum}"
        file_extension          = "pdf"
        mime_type               = "application/pdf"
        download_name           = "{cm_mkey}"
        download_name_wildcards = false
        delete_download         = false
        download_retries        = 2
        download_wait_time      = 5 # wait to before retry in seconds
        conditions              = [
          {
            field = "{cm_mostRecentReportType}" # just check there's a field and any value
          }
        ]   
        unique = ["cm_ntsbNum"] # make sure we don't have duplicates created by exploded bulkDataSource
        sort = ["cm_ntsbNum"] # sorting may help to avoid name clashes between threads
        replacements = {} # no "local" replacements
        workspaces   = [
          {
            workspace_name   = "{cm_ntsbNum}"
            workspace_type   = "Incident"
            workspace_folder = ""
          },
          {
            workspace_name   = "{airportName} ({airportId})"
            workspace_type   = "Location"
            workspace_folder = "{cm_vehicles.operatorName}"
            conditions       = [
              {
                field = "{airportName}"
              },
              {
                field = "{airportId}"
              }
            ]
          },
          {
            workspace_name   = "{cm_vehicles.make}"
            workspace_type   = "Manufacturer"
            workspace_folder = "{cm_vehicles.model}"
            conditions       = [
              {
                field = "{cm_vehicles.make}"
              }
            ]
          },
          {
            workspace_name   = "{cm_vehicles.operatorName}"
            workspace_type   = "Operator"
            conditions       = [
              {
                field = "{cm_vehicles.operatorName}"
              }
            ]
          }
        ]
      }
    ]

    ```

#### bulkItems

To bulk create items such as folders, shortcuts, or URL items, you can define a payload section `bulkItems` which can create a large number of items based on placeholders that are filled with data from a defined data source. Each `bulkItems` list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`). First, a bulk item needs a `data_source` that specifies the name of a data source in the `bulkDatasources` payload section.

These are all the settings in a single bulk item list element:

- `enabled` (bool, optional, default = true)
- `data_source` (str, mandatory)
- `force_reload` (bool, optional, default = true) - enforce a reload of the data source, e.g. useful if data source has been modified before by column operations or explosions
- `copy_data_source` (bool, optional, default = false) - to avoid side effects for repeated usage of the data source
- `explosions` (list of dicts, optional, default = [])
  - `explode_fields` (str | list, mandatory)
  - `flatten_fields` (list, optional, default = [])
  - `split_string_to_list` (bool, optional, default = false)
  - `list_splitter` (str, optional) - defines the delimiters for splitting strings in a list. Always set it if `split_string_to_list` is `true`.
- `unique` (list, optional, default = []) - list of fields (columns) that should be unique -> deduplication
- `sort` (list, optional, default = []) - list of fields to sort the data frame by
- `operations` (list, optional, default = `["create"]`) - possible values: `create`, `update`, `delete`, `recreate`
- `update_operations` (list, optional, default = `["name", "description", "categories", "url"]`) - list of update operations to apply for workspaces if `update` is included in operations (see above).
- `name` (str, mandatory) - can include placeholder surrounded by {...}
- `name_alt` (str, optional, default = None) - can include placeholder surrounded by {...}
- `name_regex` (str, optional, default = r"") - regex replacement for document names. The pattern and replacement are separated by pipe character |
- `description` (str, optional, default = None) - can include placeholder surrounded by {...}
- `nickname` (str, optional, default = None) - can include placeholder surrounded by {...}
- `categories` (list, optional, default = `[]`)
  - `name` (str, mandatory)
  - `set` (str, default = "")
  - `row` (int, optional)
  - `attribute` (str, mandatory)
  - `value` (str, optional if value_field is specified, default = None)
  - `value_field` (str, optional if value is specified, default = None) - can include placeholder surrounded by {...}
  - `value_type` (str, optional, default = `string`) - possible values: `string`, `datetime`, `list`, and `table`. If list then string with comma-separated values will be converted to a list.
  - `attribute_mapping` (dict, optional, default = None) - only relevant for value type `table` - defines a mapping from the data frame column names to the category attribute names
  - `list_splitter` (str, optional, default = `;,`) - only relevant for value type `list`. Defines the delimiter for splitting strings in a list.
  - `lookup_data_source` (str, optional, default = None)
  - `lookup_data_failure_drop` (bool, optional, default = false) - should we clear / drop values that cannot be looked up?
  - `is_key` (bool, optional, default = false) - find document is old name. For this we expect a `key` value to be defined for the bulk document and one of the category / attribute item to be marked with `is_key = true`.
- `thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `external_create_date` (str, optional, default = "")
- `external_modify_date` (str, optional, default = "")
- `key` (str, optional, default = None) - lookup key for documents other than the name
- `replacements` (list, optional, default = `[]`)
- `conditions` (list, optional, default = `[]`) - all conditions must evaluate to true
  - `field` (str, mandatory)
  - `value` (str | bool | list, optional, default = None)
  - `equal` (bool, optional): if `true` test for equality (this is the default), if `false` test for non-equality
- `workspaces` (list, optional, default = `[]`) - the workspaces the document should be uploaded to
  - `workspace_name` (str, mandatory)
  - `conditions` (list, optional, default = `[]`)
    - `field` (str, mandatory)
    - `value` (str | bool | list, optional, default = None)
    - `equal` (bool, optional): if `true` test for equality (this is the default), if `false` test for non-equality
  - `workspace_type` (str, mandatory)
  - `data_source` (str, optional, default = None)
  - `workspace_folder` (str, optional, default = "")
  - `workspace_path` (list, optional, default = `[]`)
  - `sub_workspace_type` (str, optional, default = "")
  - `sub_workspace_name` (str, optional, default = "")
  - `sub_workspace_template` (str, optional, default = "")
  - `sub_workspace_folder` (str, optional, default = "")
  - `sub_workspace_path` (list, optional, default = `[]`)

This is an example for bulkItems definitions:

=== "Terraform / HCL"

    ```terraform
    bulkItems = [
      {
        data_source       = "ntsb"
        name              = "{cm_ntsbNum}"
        type              = 0  # the type of the item. 0 = Folder, 1 = Shortcut, 140 = URL
        url               = "" # the actual URL for an url item. Empty / irrelevant if type is not 140 = URL
        original_nickname = "" # the nickname of the original item
        original_path     = [] # the top-down folder path (each folder or workspace name is a list item)
        conditions        = [
          {
            field = "{cm_mostRecentReportType}" # just check there's a field and any value
          }
        ]   
        unique = ["cm_ntsbNum"] # make sure we don't have duplicates created by exploded bulkDataSource
        sort = ["cm_ntsbNum"] # sorting may help to avoid name clashes between threads
        replacements = {} # no "local" replacements
        workspaces   = [
          {
            workspace_name   = "{cm_ntsbNum}"
            workspace_type   = "Incident"
            workspace_folder = ""
          },
          {
            workspace_name   = "{airportName} ({airportId})"
            workspace_type   = "Location"
            workspace_folder = "{cm_vehicles.operatorName}"
            conditions       = [
              {
                field = "{airportName}"
              },
              {
                field = "{airportId}"
              }
            ]
          },
          {
            workspace_name   = "{cm_vehicles.make}"
            workspace_type   = "Manufacturer"
            workspace_folder = "{cm_vehicles.model}"
            conditions       = [
              {
                field = "{cm_vehicles.make}"
              }
            ]
          },
          {
            workspace_name   = "{cm_vehicles.operatorName}"
            workspace_type   = "Operator"
            conditions       = [
              {
                field = "{cm_vehicles.operatorName}"
              }
            ]
          }
        ]
      }
    ]

    ```

#### bulkClassifications

To bulk create classifications (items in the Classification Volume of Content Server) you can define a payload section `bulkClassifications` which can create, update or delete a large number of classifications based on placeholders that are filled with data from a defined data source. The rows of the data source are processed in parallel by multiple threads. Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`). First, a bulk classification needs a `data_source` that specifies the name of a data source in the `bulkDatasources` payload section.

These are all the settings in a single bulk classification list element:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `data_source` (str, mandatory) - name of the data source in the `bulkDatasources` payload section
- `force_reload` (bool, optional, default = `true`) - enforce a reload of the data source, e.g. useful if data source has been modified before by column operations or explosions
- `copy_data_source` (bool, optional, default = `false`) - to avoid side effects for repeated usage of the data source
- `explosions` (list of dicts, optional, default = `[]`)
  - `explode_fields` (str | list, mandatory) - the field(s) (columns) with list values to explode into multiple rows
  - `flatten_fields` (list, optional, default = `[]`)
  - `split_string_to_list` (bool, optional, default = `false`)
  - `list_splitter` (str, optional, default = `,`) - defines the delimiters for splitting strings in a list.
- `filters` (list of dicts, optional, default = `[]`) - only keep the data rows that match all filter conditions. Filters are applied after the explosions and before sorting and deduplication. Each filter has a `field` (name of a column in the data source), a `value` (str | list; if it is a list one of the values must match) and optionally `equal` (bool, default = `true`), `regex` (bool, default = `false`) and `enabled` (bool, default = `true`).
- `sort` (list, optional, default = `[]`) - list of fields (columns) to sort the data frame by
- `unique` (list, optional, default = `[]`) - list of fields (columns) that should be unique -> deduplication. Deduplication is done after sorting and always keeps the first matching row.
- `operations` (list, optional, default = `["create"]`) - possible values: `create`, `update`, `delete`, `recreate`. `delete` is only executed if `conditions_delete` is defined. `recreate` deletes an existing classification (with purge) and creates it again.
- `update_operations` (list, optional, default = `["name", "description", "categories", "nickname"]`) - list of update operations to apply for classifications if `update` is included in `operations`
- `path` (list, optional, default = `[]`) - the top-down path of parent classifications in the Classification Volume under which the classification is created (each list element is a classification name, can include placeholder surrounded by {...}). If the path is empty (or if a placeholder cannot be resolved) the classification is created directly in the Classification Volume. Missing path elements are only created automatically if `key` is used.
- `name` (str, mandatory) - name of the classification, can include placeholder surrounded by {...}. Rows where the name cannot be resolved are skipped.
- `name_alt` (str, optional, default = None) - alternative name that is used if `name` cannot be resolved, can include placeholder surrounded by {...}
- `description` (str, optional, default = None) - can include placeholder surrounded by {...}
- `description_alt` (str, optional, default = None) - alternative description that is used if `description` cannot be resolved, can include placeholder surrounded by {...}
- `nickname` (str, optional, default = None) - nickname of the classification, can include placeholder surrounded by {...}. The value is converted to lower case and spaces and hyphens are replaced by underscores.
- `nickname_alt` (str, optional, default = None) - alternative nickname that is used if `nickname` cannot be resolved, can include placeholder surrounded by {...}
- `key` (str, optional, default = None) - lookup key for classifications other than the name, can include placeholder surrounded by {...}. If a key is defined then one of the category attributes must be marked with `is_key = true`. An existing classification is then found by the value of this attribute (and not by its name), which allows to rename classifications.
- `external_create_date` (str, optional, default = None) - can include placeholder surrounded by {...}
- `external_modify_date` (str, optional, default = None) - can include placeholder surrounded by {...}. For `update` operations the classification is only updated if this date is newer than the modification date of the existing classification.
- `thread_number` (int, optional, default = value of the environment variable `BULK_THREAD_NUMBER`, or `1`) - number of parallel threads
- `replacements` (dict, optional, default = None) - replacements that are applied to the values read from the data source. The dictionary key is the field name and the value is a list of replacement rules.
- `conditions` (list, optional, default = `[]`) - all conditions must evaluate to true, otherwise the data row is skipped
  - `field` (str, mandatory) - can include placeholder surrounded by {...}
  - `value` (str | bool | list, optional, default = None) - if not specified only the existence of a value for the field is tested. If it is a list one of the list values must match.
  - `equal` (bool, optional, default = `true`): if `true` test for equality, if `false` test for non-equality
- `conditions_create` (list, optional, default = `[]`) - same syntax as `conditions`. If defined and not met by a data row, the `create` and `recreate` operations are not executed for this row.
- `conditions_update` (list, optional, default = `[]`) - same syntax as `conditions`. If defined and not met by a data row, the `update` operation is not executed for this row.
- `conditions_delete` (list, optional, default = `[]`) - same syntax as `conditions`. If not defined or not met by a data row, the `delete` operation is not executed for this row.
- `categories` (list, optional, default = `[]`) - categories and attributes to set on the classification
  - `name` (str, mandatory) - name of the category
  - `set` (str, optional, default = "") - name of the attribute set (if the attribute is part of a set)
  - `row` (int, optional) - row number for attributes in multi-row sets
  - `attribute` (str, mandatory) - name of the attribute
  - `value` (str, optional if `value_field` is specified, default = None)
  - `value_field` (str, optional if `value` is specified, default = None) - can include placeholder surrounded by {...}
  - `value_field_alt` (str, optional, default = None) - alternative value field that is used if `value_field` cannot be resolved, can include placeholder surrounded by {...}
  - `value_type` (str, optional, default = `string`) - possible values: `string`, `datetime`, `list`, and `table`. If `list` then a string with delimiter-separated values will be converted to a list.
  - `attribute_mapping` (dict, optional, default = None) - only relevant for value type `table` - defines a mapping from the data frame column names to the category attribute names
  - `list_splitter` (str, optional, default = `;,`) - only relevant for value type `list`. Defines the delimiters for splitting strings in a list.
  - `value_mapping` (dict, optional, default = None) - maps original values to the values to be written to the attribute
  - `sort_multi_values` (bool, optional, default = `false`) - sort the values of a multi-value attribute alphabetically
  - `lookup_data_source` (str, optional, default = None) - name of a data source used to look up a synonym for the value
  - `lookup_data_failure_drop` (bool, optional, default = `false`) - should we clear / drop values that cannot be looked up?
  - `is_key` (bool, optional, default = `false`) - marks the attribute that stores the value of the `key` of the bulk classification

If a classification (with the same name or, if `key` is used, with the same key) already exists it is skipped unless `update`, `delete` or `recreate` is requested. If a nickname is defined and a classification with this nickname already exists, then the classification is skipped as well (unless `update` or `delete` is requested). Classifications that were successfully processed are recorded so that a repeated run does not try to process them again.

This is an example for bulkClassifications definitions:

=== "Terraform / HCL"

    ```terraform
    bulkClassifications = [
      {
        enabled           = true
        data_source       = "contract-types"
        path              = ["Contracts", "{region}"]
        name              = "{contractType}"
        name_alt          = "{contractTypeCode}"
        description       = "Contract type {contractType}"
        nickname          = "{contractTypeCode}"
        operations        = ["create", "update"]
        update_operations = ["name", "description"]
        unique            = ["contractTypeCode"]
        sort              = ["contractTypeCode"]
        conditions = [
          {
            field = "{contractType}"
          }
        ]
        conditions_update = [
          {
            field = "{status}"
            value = ["changed", "new"]
          }
        ]
        categories = [
          {
            name        = "Classification Attributes"
            attribute   = "Code"
            value_field = "{contractTypeCode}"
            is_key      = true
          }
        ]
        key = "{contractTypeCode}"
      }
    ]
    ```

=== "YAML"

    ```yaml
    bulkClassifications:
    - enabled: true
      data_source: contract-types
      path:
      - Contracts
      - "{region}"
      name: "{contractType}"
      name_alt: "{contractTypeCode}"
      description: Contract type {contractType}
      nickname: "{contractTypeCode}"
      operations:
      - create
      - update
      update_operations:
      - name
      - description
      unique:
      - contractTypeCode
      sort:
      - contractTypeCode
      conditions:
      - field: "{contractType}"
      conditions_update:
      - field: "{status}"
        value:
        - changed
        - new
      categories:
      - name: Classification Attributes
        attribute: Code
        value_field: "{contractTypeCode}"
        is_key: true
      key: "{contractTypeCode}"
    ```

### Advanced Customizing Syntax

For advanced use cases that are not covered by OpenText Content Management or OTDS APIs, there are additional customizing capabilities.
This includes calling SAP Remote Function Calls (RFC), executing commands in the Kubernetes Pods or triggering web hooks (HTTP POST requests):

#### kubernetes

This payload type allows to apply commands via the Kubernetes API. Currently the actions `restart` and `execPodCommands` are supported.

##### action="restart"

`restart` can be used with type (deployment, statefulset, pod). For `deployment` and `statefulset` a rolling deployment will be triggered. In case of "pod" it will be deleted and it is expected that the Kubernetes API automatically recreates it. This will not work if the pod was created as a standalone instance.

##### action="execPodCommands"

`execPodCommands` is used to execute a Linux command inside a Kubernetes pod using the Kubernetes API (similar to what `kubectl exec` does). This may be handy to influence / change some of the intrinsics of the pods. If `enabled` evaluates to `true` then the command will be called during the customization process. The `pod_name` must match the technical name of the pod in the Kubernetes deployment (you can get the pod names with `kubectl get pods`). `command` is a list of the command terms and parameters. The first element is typically the Linux shell that is used for executing the command and the second parameter is typically `-c` if the command is run in non-interactive mode. `interactive` defines if the command is run interactively or not. The default is to run the command non-interactively. Only for longer running commands you should prefer to run the command interactively.

=== "Terraform / HCL"

    ```terraform
    kubernetes = [
        {
          enabled     = true
          action      = "execPodCommands"
          description = "Test"
          pod_name    = "otcs-admin-0"
          command     = ["/bin/sh", "-c", "touch /tmp/python_was_here"]
          interactive = false
        },
        {
          enabled     = true
          action      = "restart"
          type        = "deployment"
          name        = "otdsws"
        },
        {
          enabled     = true
          action      = "restart"
          type        = "statefulset"
          name        = "otcs-frontend"
        }
    ]
    ```

=== "YAML"

    ```yaml
    kubernetes:
    - action: execPodCommands
      command:
      - /bin/sh
      - -c
      - touch /tmp/python_was_here
      description: Test
      enabled: true
      interactive: false
      pod_name: otcs-admin-0
    - action: restart
      type: deployment
      name: otdsws
    - action: restart
      type: statefulset
      name: otcs-frontend
    ```

#### execPodCommands (deprecated)

**use `kubernetes` with action `execPodCommands`**

`execPodCommands` is used to execute a Linux command inside a Kubernetes pod using the Kubernetes API (similar to what `kubectl exec` does). This may be handy to influence / change some of the intrinsics of the pods. If `enabled` evaluates to `true` then the command will be called during the customization process. The `pod_name` must match the technical name of the pod in the Kubernetes deployment (you can get the pod names with `kubectl get pods`). `command` is a list of the command terms and parameters. The first element is typically the Linux shell that is used for executing the command and the second parameter is typically `-c` if the command is run in non-interactive mode. `interactive` defines if the command is run interactively or not. The default is to run the command non-interactively. Only for longer running commands you should prefer to run the command interactively.

=== "Terraform / HCL"

    ```terraform
    execPodCommands = [
        {
          enabled     = false
          description = "Test"
          pod_name    = "otcs-admin-0"
          command     = ["/bin/sh", "-c", "touch /tmp/python_was_here"]
          interactive = false
        }
    ]
    ```

=== "YAML"

    ```yaml
    execPodCommands:
    - command:
      - /bin/sh
      - -c
      - touch /tmp/python_was_here
      description: Test
      enabled: false
      interactive: false
      pod_name: otcs-admin-0

    ```

#### execCommands

`execCommands` is used to execute a command in the local customizer pod. `command` is a list of the command terms and parameters. The first element is typically the Linux shell that is used for executing the command and the second parameter is typically `-c`.

=== "Terraform / HCL"

    ```terraform
    execCommands = [
        {
          enabled     = false
          description = "Test"
          command     = ["/bin/sh", "-c", "touch /tmp/python_was_here"]
        }
    ]
    ```

=== "YAML"

    ```yaml
    execCommands:
    - command:
      - /bin/sh
      - -c
      - touch /tmp/python_was_here
      description: Test
      enabled: false

    ```

#### execDatabaseCommands

`execDatabaseCommands` is used to execute commands in a database. If `enabled` evaluates to `true` then the database command set is active.
Each item in the `execDatabaseCommands` list consists of a database connection `db_connection` and a list of commands `db_commands` to execute in that database. Each command can have a list of associated parameters `params`. If params is not empty then the command must have placeholders given by `%s` that are replaced by the parameters from the `params` list in the given ordering.

=== "Terraform / HCL"

    ```terraform
    execDatabaseCommands = [
        {
          enabled       = false
          db_connection = {
            db_name     = "otcs"
            db_hostname = "localhost"
            db_port     = 5432
            db_username = "test"
            db_password = "123"
          }
          db_commands = [
            {
              command = "select * from dtree where name = %s"
              params  = ["Test"]
            }
          ]
        }
    ]
    ```

=== "YAML"

    ```yaml
    execDatabaseCommands:
    - enabled: false
      db_connection:
        db_name: "otcs"
        db_hostname: "localhost"
        db_port: 5432
        db_username: "test"
        db_password: "123"
      db_commands:
      - command: "select * from dtree where name = %s"
        params: ["Test"]
    ```

#### webHooks

`webHooks` and `webHooksPost` are used to call (HTTP request) defined URLs that may trigger certain activities as webhooks. `webHooks` is called at the beginning of the customization process and `webHooksPost` is called at the end.

If `enabled` evaluates to `true` then the webhook is active.

`url` defines the URL of the web hook. `method` can be one of the typical HTTP request types (POST, GET, PUT, ...). If it is omitted the default is `POST`. `description` should describe the purpose of the web hook. The parameters `payload` and `headers` are maps (dictionaries) of name, value pairs. These are passed as additional header or body values to the HTTP request.

=== "Terraform / HCL"

    ```terraform
    webHooks = [
      {
        enabled     = var.enable_sap
        url         = "https://.../start_sap"
        method      = "POST"
        description = "Start SAP S/4HANA Web Hook"
        payload     = {
            parameter = "value"
        }
        headers     = {} # if empty a standard header will be set
      }
    ]
    webHooksPost = [
      {
        enabled     = var.enable_sap
        url         = "https://.../stop_sap"
        method      = "POST"
        description = "Stop SAP S/4HANA Web Hook"
        payload     = {}
        headers     = {} # if empty a standard header will be set
      }
    ]
    ```

=== "YAML"

    ```yaml
    webHooks:
    - description: Start SAP S/4HANA Web Hook
      enabled: ${var.enable_sap}
      headers: {}
      method: POST
      payload:
        parameter: value
      url: https://.../start_sap
    webHooksPost:
    - description: Stop SAP S/4HANA Web Hook
      enabled: ${var.enable_sap}
      headers: {}
      method: POST
      payload: {}
      url: https://.../stop_sap
    ```

#### sapRFCs

The `sapRFCs` payload defines a list of SAP Remote Function Calls (RFC) that are called to automate things in SAP S/4HANA. If `enabled` evaluates to `true` then the RFC will be called during the customization process. `name` is the technical SAP name of the RFC. `description` is optional and is just informative. If the RFC requires parameters they can be passed via the `parameters` block (name, value pairs).

=== "Terraform / HCL"

    ```terraform
    sapRFCs = [
        {
          enabled     = var.enable_sap
          name        = "SM02_ADD_MESSAGE"
          description = "Write message into SAP message center"
          parameters = {
              "MESSAGE" = "Start processing Terrarium RFC calls..."
          }
        },
        {
          enabled     = var.enable_sap
          name        = "ZFM_GECKO_RFC_CR_UPD_ALL_WKSP"
          description = "Create workspace for all SAP Customers (KNA1)"
          parameters = {
              "OBJECTTYPE" = "KNA1"
              "OBJECTKEY"  = ""
              "SYNC"       = ""
          }
        }
    ]
    ```

=== "YAML"

    ```yaml
    sapRFCs:
    - description: Write message into SAP message center
      enabled: ${var.enable_sap}
      name: SM02_ADD_MESSAGE
      parameters:
        MESSAGE: Start processing Terrarium RFC calls...
    - description: Create workspace for all SAP Customers (KNA1)
      enabled: ${var.enable_sap}
      name: ZFM_GECKO_RFC_CR_UPD_ALL_WKSP
      parameters:
        OBJECTKEY: ''
        OBJECTTYPE: KNA1
        SYNC: ''
    ```

#### Browser Automations

`browserAutomations` is a list of browser automation for things that can only be
automated via the web user interface. Each list element is a dict with these keys:

- `enabled` (bool, optional, default = True)
- `name` (str, mandatory)
- `description` (str, optional)
- `base_url` (str, mandatory)
- `user_name` (str, optional)
- `password` (str, optional)
- `wait_time` (float, optional, default = 45.0) - wait time in seconds
- `wait_until` (str, optional) - the page load / navigation `wait until` strategy. Possible values: `load`, `networkidle`, `domcontentloaded`
- `headless` (bool, optional) - run the browser without a visible window. Defaults to the global Customizer setting.
- `browser` (str, optional) - the browser to use: `webkit`, `chromium` or `firefox`. Defaults to the environment variable `BROWSER`, or `webkit` if it is not set.
- `debug` (bool, optional, default = False) - if True take screenshots and save to customizer pod
- `automations` (list, mandatory)
  - `dependent` (bool, optional, default = true) - decide if current automation step is dependent on the previous step. If dependent = True and previous step failed this step is skipped.
  - `type` (str, optional, default = "") - possible types: `login`, `get_page`, `click_elem`, `set_elem`, `check_elem`
  - `page` (str, optional, default = "") - the page-specific part of the URL. Will be concatenated with the `base_url`
  - `selector` (str, optional, default = "") - the selector (search pattern) for the page element
  - `selector_type` (str, optional, default = "id") - the type of the selector - either `id`, `name`, `css`, `xpath`, `role`, `text`, `title`, `label`, `placeholder`, `alt`
  - `role_type` (str, optional, default = "") - the ARIA role of an element. Only relevant for find = `role`.
  - `scroll_to_element` (bool, optional, default = true) - scroll to the element before clicking it - for type `click_elem` only. Should actually not be necessary as locators should scroll automatically.
  - `value` (str, optional, default = "") - the new value of element. Relevant for type = `set_elem`.
  - `user_field` (str, optional, default = "") - the name of the HTML field holding the user name - only for type `login`.
  - `password_field` (str, optional, default = "") - the name of the HTML field holding the password - only for type `login`.
  - `iframe`: name of the iframe if the elem is inside an iframe
  - `press_enter`: simulate pressing the "Enter" key after setting the elem value - for type `set_elem` only
  - `typing` (bool, optional) - deciding if to simulate keyboard input - this is required for many type-ahead fields to work - for type `set_elem` only
  - `exact_match` (bool, optional) - deciding if the element should be identified with an exact match
  - `hover_only` (bool, optional) - deciding if instead of clicking the element only a mouse over hovering should be simulated - for type `click_elem` only
  - `wait_until` (str, optional, default = "") - an automation-step specific value for `wait_until` (see above)
  - `volume` (int, optional, default = 141 (Enterprise Volume)) - the OTCS volume ID. Only relevant for type = `get_page`.
  - `path` (list, optional, default = []) - a top-down list of folder / workspace names. Only relevant for type = `get_page`.
  - `navigation` (bool, optional, default = False) - whether or not the click issues a navigation event. Relevant only for type = `click_elem`.
  - `popup_window` (bool, optional) - deciding if the click will popup a new browser window - for type `click_elem` only
  - `close_window` (bool, optional) - deciding if the click will close the current window - for type `click_elem` only
  - `checkbox_state` (bool, optional, default = None) - defines the desired state of a checkbox element (True = checked, False = unchecked)
  - `attribute` (str, optional, default = "") - the attribute name of an HTML element. Relevant only for type = `check_elem`.
  - `substring` (bool, optional, default = False) - whether or not a string comparison should consider substrings. Relevant only for type = `check_elem`.
  - `min_count` (int, optional, default = 1) - defines how many elements should be found at a minimum by type = `check_elem`.
  - `want_exist` (bool, optional, default = True) - defines for type = `check_elem` if the existence or non-existence should be checked.
  - `iframe` (str, optional) - name of the iframe tag if the element is inside an iframe.
  - `exact_match` - if the element name should be an exact match
  - `regex` (bool, optional) - is the name to be interpreted as a regular expression?

---

#### testAutomations

`testAutomations` is processed by exactly the same logic as [Browser Automations](#browser-automations). It is intended for browser-based (Playwright) tests of the deployed system rather than for configuration tasks. Each list element supports the same fields as in [Browser Automations](#browser-automations) (`enabled`, `name`, `description`, `base_url`, `user_name`, `password`, `wait_time`, `wait_until`, `debug`, `automations` and all automation step fields); please refer to that section instead of repeating them here.

The only differences are:

- In the log output the elements are called "Test automation" instead of "Browser automation".
- The processing status of the section is tracked separately under the section name `testAutomations`, so it is run (or skipped after a successful run) independently of `browserAutomations`.

=== "Terraform / HCL"

    ```terraform
    testAutomations = [
      {
        enabled     = true
        name        = "Check Login"
        description = "Verify that a user can log in"
        base_url    = "https://content.example.com"
        user_name   = "jdoe"
        password    = "secret"
        automations = [
          {
            type = "login"
            page = "/otcs/cs.exe"
          },
          {
            type          = "check_elem"
            selector      = "Enterprise"
            selector_type = "text"
          }
        ]
      }
    ]
    ```

=== "YAML"

    ```yaml
    testAutomations:
    - enabled: true
      name: Check Login
      description: Verify that a user can log in
      base_url: https://content.example.com
      user_name: jdoe
      password: secret
      automations:
      - type: login
        page: /otcs/cs.exe
      - type: check_elem
        selector: Enterprise
        selector_type: text
    ```

### Search Aviator Customizing Syntax

#### avtsRepositories

`avtsRepositories` is used to define Search Aviator repositories.

These are all the settings in a single repository list element:

- `enabled`: true/false
- `name`: Name of the Repository needs to be unique
- `type`: AVTS repository type:
  - Extended ECM
  - Documentum

##### OpenText Content Management specific values

- `otcs_url`: URL of Content Server (OTCS), e.g. `https://otcs.domain.tld/cs/cs`
- `otcs_api_url`: URL of Content Server (OTCS), e.g. `https://otcs.domain.tld/cs/cs`
- `username`: Username for Content Server crawling
- `password`: Password for the crawling user
- `node_id`: Node ID of the Content Server root folder

##### Documentum specific values

`to be done`

=== "Terraform / HCL"

    ```terraform
      avtsRepositories = [
        {
          enabled  = true
          name     = "OpenText Content Management"
          type     = "Extended ECM"
          otcs_url = "https://otcs.domain.tld/cs/cs"
          otcs_api_url = "http://otcs-frontend/cs/cs"
          username = "admin"
          password = "********"
          node_id  = 2000
          start    = true
        },
        {
          enabled = true
          name    = "Microsoft Teams"
          start   = true
          type    = "MSTeams"

          client_id            = "XXXX"
          tenant_id            = "XXXX"
          certificate_file     = "/certificates/certificate.pfx"
          certificate_password = "XXXX"

          index_attachments     = true
          index_call_recordings = true
          index_message_replies = true
          index_user_chats      = true
        },
        {
          enabled = true
          name    = "SharePoint"
          start   = true
          type    = "SharePoint"

          client_id            = "XXXX"
          tenant_id            = "XXXX"
          certificate_file     = "/certificates/certificate.pfx"
          certificate_password = "XXXX"

          sharepoint_url_type   = "SiteCollection"
          sharepoint_url        = "https://xxx.sharepoint.com"
          sharepoint_mysite_url = "https://xxx.sharepoint.com/sites/Innovate/"
          sharepoint_admin_url  = "https://xxx.admin.com"
          index_user_profiles   = false
        }      
    ]
    ```

=== "YAML"

    ```yaml
    ```

#### avtsQuestions

`avtsQuestions` sets the list of sample questions that Aviator Search proposes to users. It is a single dictionary (not a list). The questions are sent to Aviator Search after authentication; existing proposed questions are replaced by the given list.

The dictionary has these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload section on or off
- `questions` (list of str, optional, default = `[]`) - the sample questions to be proposed in Aviator Search

=== "Terraform / HCL"

    ```terraform
    avtsQuestions = {
      enabled   = true
      questions = [
        "What are the payment terms of the contract?",
        "Which documents were updated last week?",
        "Summarize the key risks of this project."
      ]
    }
    ```

=== "YAML"

    ```yaml
    avtsQuestions:
      enabled: true
      questions:
      - What are the payment terms of the contract?
      - Which documents were updated last week?
      - Summarize the key risks of this project.
    ```

### Content Aviator Customizing Syntax

#### embeddings

`embeddings` triggers the embedding of metadata (and optionally documents and images) into Content Aviator, using the FEME embedding tool. The section can also be named `feme` in `payloadSections`. It is processed for each list element; the target nodes can be given by node ID, by nickname or by workspace type.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `id` (int, optional) - ID of the node to embed. If set, `nickname` and `workspace_types` are ignored.
- `nickname` (str, optional) - nickname of the node to embed. Only used if `id` is not set.
- `workspace_types` (str or list of str, optional) - name(s) of workspace types. All workspace instances of these types are embedded. Only used if neither `id` nor `nickname` resolves to a node.
- `wait_for_completion` (bool, optional, default = `true`) - wait until the embedding has finished
- `crawl` (bool, optional, default = `false`) - run the task as a "crawl" instead of an "index"
- `document_metadata` (bool, optional, default = `false`) - embed the metadata of documents. The legacy key `documents` is used if `document_metadata` is not present.
- `workspace_metadata` (bool, optional, default = `false`) - embed the metadata of workspaces. The legacy key `workspaces` is used if `workspace_metadata` is not present.
- `images` (bool, optional, default = `false`) - embed images

=== "Terraform / HCL"

    ```terraform
    embeddings = [
      {
        enabled             = true
        nickname            = "contracts_folder"
        wait_for_completion = true
        crawl               = true
        document_metadata   = true
        images              = false
      },
      {
        enabled            = true
        workspace_types    = ["Contract", "Customer"]
        workspace_metadata = true
      }
    ]
    ```

=== "YAML"

    ```yaml
    embeddings:
    - enabled: true
      nickname: contracts_folder
      wait_for_completion: true
      crawl: true
      document_metadata: true
      images: false
    - enabled: true
      workspace_types:
      - Contract
      - Customer
      workspace_metadata: true
    ```

#### aviatorMcpServers

`aviatorMcpServers` creates MCP (Model Context Protocol) server configurations in Content Aviator. The section is only processed if Content Aviator is configured; otherwise a warning is logged and it is skipped.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off. The value is also passed to Content Aviator as the "active" state of the server.
- `name` (str, mandatory) - unique name of the MCP server
- `transport` (str, optional, default = `streamable_http`) - transport type: `streamable_http`, `sse` or `stdio`
- `url` (str, mandatory for transport `streamable_http` and `sse`) - URL of the MCP server
- `command` (str, mandatory for transport `stdio`) - command to start the MCP server
- `args` (list of str, optional) - arguments for the `stdio` command
- `tool_scope` (str, optional) - where the tools of the server are available: `default` or `custom`
- `auth_schema` (dict, optional) - authentication configuration, passed as is to Content Aviator

=== "Terraform / HCL"

    ```terraform
    aviatorMcpServers = [
      {
        enabled    = true
        name       = "Contract Tools"
        transport  = "streamable_http"
        url        = "https://mcp.domain.tld/mcp"
        tool_scope = "default"
      },
      {
        enabled   = true
        name      = "Local Tools"
        transport = "stdio"
        command   = "npx"
        args      = ["-y", "example-mcp-server"]
      }
    ]
    ```

=== "YAML"

    ```yaml
    aviatorMcpServers:
    - enabled: true
      name: Contract Tools
      transport: streamable_http
      url: https://mcp.domain.tld/mcp
      tool_scope: default
    - enabled: true
      name: Local Tools
      transport: stdio
      command: npx
      args:
      - -y
      - example-mcp-server
    ```

#### aviatorMcpTools

`aviatorMcpTools` registers additional MCP tools (Content Aviator agents) in Content Aviator. Tools that are already registered are skipped. The section is only processed if Content Aviator is configured; otherwise a warning is logged and it is skipped.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `name` (str, mandatory) - name of the tool to register

=== "Terraform / HCL"

    ```terraform
    aviatorMcpTools = [
      {
        enabled = true
        name    = "contract_search"
      },
      {
        enabled = false
        name    = "document_summary"
      }
    ]
    ```

=== "YAML"

    ```yaml
    aviatorMcpTools:
    - enabled: true
      name: contract_search
    - enabled: false
      name: document_summary
    ```

### AppWorks Platform Customizing Syntax

#### appworks

`appworks` configures OpenText AppWorks Platform organizations. For each organization the Customizer first (optionally) sets up the OTDS resource, access role, license and Kubernetes configuration, then creates the AppWorks workspaces, publishes their projects and finally creates entities (categories, priorities, case types, customers, cases). The section requires that OTDS, Content Server, AppWorks Platform and Kubernetes access are configured.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `organization` (str, mandatory) - name of the AppWorks organization
- `resource_config` (bool, optional, default = `false`) - if `true`, the OTDS resource `<organization>` is created (if missing), the Content Server and admin partitions are added to the OTDS access role `Access to <organization>`, the AppWorks license is assigned (if a license file is available), the organization configuration in the Kubernetes config map is updated and the AppWorks stateful set is restarted. If `false`, this part is skipped.
- `workspaces` (list, optional) - list of AppWorks workspaces to create and synchronize. If missing, no workspaces or entities are processed for the organization.
    - `workspace_id` (str, mandatory) - ID of the workspace
    - `name` (str, mandatory) - name of the workspace
    - `path` (str, mandatory) - directory in the AppWorks pod that contains the project artifacts. For a newly created workspace the content of this directory is copied into the workspace.
    - `projects` (list, optional) - list of projects in the workspace that are published
        - `name` (str, mandatory) - name of the project
        - `documentId` (str, mandatory) - document ID of the project
- `entities` (list, optional) - list of entities to create in the organization. Existing categories, priorities, case types and customers (identified by name) are skipped.
    - `type` (str, mandatory) - one of `category`, `priority`, `caseType`, `customer`, `case`
    - `name` (str, mandatory for all types except `case`) - name of the entity
    - `description` (str, optional, default = `""`) - description (types `category`, `priority`, `caseType`, `case`)
    - `status` (int, optional, default = `1`) - status of the entity (types `category`, `priority`, `caseType`)
    - `prefix` (str, only for type `category`) - case prefix of the category
    - `sub_entities` (list, optional, only for type `category`) - sub categories. Each element has `type` (must be `subCategory`), `name`, `description` (optional, default = `""`) and `status` (optional, default = `1`).
    - `legal_business_name` (str, optional, default = `""`) - only for type `customer`
    - `trading_name` (str, optional, default = `""`) - only for type `customer`
    - `subject` (str, mandatory for type `case`) - subject of the case
    - `category` (str, optional) - name of an existing category. Only for type `case`.
    - `sub_category` (str, optional) - name of a sub category of the category. Only for type `case`.
    - `priority` (str, optional) - name of an existing priority. Only for type `case`.
    - `case_type` (str, optional) - name of an existing case type. Only for type `case`.
    - `customer` (str, optional) - name of an existing customer. Only for type `case`.
    - `loan_amount` (int, optional, default = `1`) - only for type `case`
    - `loan_duration_in_month` (int, optional, default = `2`) - loan duration in months. Only for type `case`.

=== "Terraform / HCL"

    ```terraform
    appworks = [
      {
        enabled         = true
        organization    = "contracts"
        resource_config = true
        workspaces = [
          {
            workspace_id = "contractsWorkspace"
            name         = "Contract Management"
            path         = "/opt/appworks/projects/contracts"
            projects = [
              {
                name       = "ContractApp"
                documentId = "0a1b2c3d-1111-2222-3333-444455556666"
              }
            ]
          }
        ]
        entities = [
          {
            type        = "category"
            name        = "Loans"
            description = "Loan cases"
            prefix      = "LN"
            sub_entities = [
              {
                type = "subCategory"
                name = "Personal Loans"
              }
            ]
          },
          {
            type = "priority"
            name = "High"
          },
          {
            type = "caseType"
            name = "Standard"
          },
          {
            type                = "customer"
            name                = "Example Corp"
            legal_business_name = "Example Corporation Ltd."
            trading_name        = "Example"
          },
          {
            type                   = "case"
            subject                = "Loan request Example Corp"
            category               = "Loans"
            sub_category           = "Personal Loans"
            priority               = "High"
            case_type              = "Standard"
            customer               = "Example Corp"
            loan_amount            = 10000
            loan_duration_in_month = 12
          }
        ]
      }
    ]
    ```

=== "YAML"

    ```yaml
    appworks:
    - enabled: true
      organization: contracts
      resource_config: true
      workspaces:
      - workspace_id: contractsWorkspace
        name: Contract Management
        path: /opt/appworks/projects/contracts
        projects:
        - name: ContractApp
          documentId: 0a1b2c3d-1111-2222-3333-444455556666
      entities:
      - type: category
        name: Loans
        description: Loan cases
        prefix: LN
        sub_entities:
        - type: subCategory
          name: Personal Loans
      - type: priority
        name: High
      - type: caseType
        name: Standard
      - type: customer
        name: Example Corp
        legal_business_name: Example Corporation Ltd.
        trading_name: Example
      - type: case
        subject: Loan request Example Corp
        category: Loans
        sub_category: Personal Loans
        priority: High
        case_type: Standard
        customer: Example Corp
        loan_amount: 10000
        loan_duration_in_month: 12
    ```

### Knowledge Discovery Customizing Syntax

#### nifi

`nifi` uploads Apache NiFi flows (process groups) to OpenText Knowledge Discovery and sets their parameters. It requires that Knowledge Discovery is configured. If a flow with the same `name` already exists, it is not uploaded again and not started; only its parameters are updated.

Each list element is a dictionary with these fields:

- `enabled` (bool, optional, default = `true`) - switch to turn the payload element on or off
- `name` (str, mandatory) - name of the NiFi flow (process group)
- `file` (str, mandatory) - path to the flow definition file (JSON) that is uploaded to NiFi
- `position_x` (float, optional, default = `0.0`) - X position of the flow on the NiFi canvas
- `position_y` (float, optional, default = `0.0`) - Y position of the flow on the NiFi canvas
- `start` (bool, optional, default = `false`) - if `true`, all processors of a newly uploaded flow are started and its controller services are enabled
- `parameters` (list, optional, default = `[]`) - list of parameters to set in the flow. Each element has these fields:
    - `component` (str, mandatory) - name of the NiFi component that holds the parameter
    - `name` (str, mandatory) - name of the parameter
    - `value` (str, mandatory) - value of the parameter. An empty value is treated as missing.
    - `description` (str, optional, default = `""`) - description of the parameter
    - `sensitive` (bool, optional, default = `false`) - whether the parameter is a sensitive value (it is not written to the log)

=== "Terraform / HCL"

    ```terraform
    nifi = [
      {
        enabled    = true
        name       = "Document Ingestion"
        file       = "/payload/nifi/document-ingestion.json"
        position_x = 100.0
        position_y = 200.0
        start      = true
        parameters = [
          {
            component   = "Document Ingestion Parameters"
            name        = "source_url"
            value       = "https://content.example.com"
            description = "URL of the content source"
          },
          {
            component = "Document Ingestion Parameters"
            name      = "api_password"
            value     = "secret"
            sensitive = true
          }
        ]
      }
    ]
    ```

=== "YAML"

    ```yaml
    nifi:
    - enabled: true
      name: Document Ingestion
      file: /payload/nifi/document-ingestion.json
      position_x: 100.0
      position_y: 200.0
      start: true
      parameters:
      - component: Document Ingestion Parameters
        name: source_url
        value: https://content.example.com
        description: URL of the content source
      - component: Document Ingestion Parameters
        name: api_password
        value: secret
        sensitive: true
    ```

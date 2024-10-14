# Payload Syntax

## Customizing

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
    - `dictionary`: a group of values identified by named labels, like `{name = "nwheeler", security_clearance = 50}`.
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

### OTDS Customizing Syntax

The payload syntax for OTDS customizing uses the following lists (the list elements are maps):

#### resources

`resources` allows to create new resources in OTDS.

Each list element includes a switch `enabled` to turn them on or off. This switch can be controlled by a Terraform variable.

In addition, each resource definition has a `name`, an optional `description`, and an optional `display_name`. It is also possible to activate the new resource via the `activate = true`. With `resource_id` and `secret` pre-defined values can be provided for the resource ID and the secret. The `secret`should be 24 characters long and end with `==`. If a secret and a resource ID are provided, then the resource is automatically activated. Otherwise you can enforce activation with `activate = true`. With `additional_payload` a dictionary of key value pairs can be provided:

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
          "pcCreatePermissionAllowed": True,
          "pcModifyPermissionAllowed": True,
          "pcDeletePermissionAllowed": False,
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

In addition, each synchronized partition has a `name`, an optional `description`. It is also possible to directly put the new synchronized partition into an existing `access_role`. Also `licenses` this synchronized partition should be assigned to can be specified:

In case of importing Active Directory users and groups ignore licenses. 

=== "Terraform / HCL"

    ```terraform
    synchronizedPartitions: [
      {
        access_role = Access to cs,
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
            ## add all the requied attributes as mentioned in below format
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
            ## add all the requied attributes as mentioned in below format
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

#### oauthClients

`oauthClients` allows to create a list of new OAuth client in OTDS.

Each list element includes a switch `enabled` to turn them on or off. This switch can be controlled by a Terraform variable.

`name` defines the name of the OTDS OAuth client and `description` should describe what the OAuth client is used for. Each OAuth client has the typical elements such as `confidential` (default is `true`), OTDS `partition` (default is `Global`), a `redirect_url`, `permission_scope`, `default_scope`, and `allow_impersonation`. If there's a predefined secret it can be provided by `secret`.

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
    ```

#### authHandlers

`authHandlers` is a list of additional OTDS authentication handlers. 

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, each handler has a `name`, `type` and an optional `description`. Further values can be specified that depends on the type of the handler. Supported types are `SAML`, `OAUTH`, or `SAP`. The values can also use terraform variables.

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
        otds_url               = "https://${local.otds_dns_name}/otdsws/login" # required for SAML
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
        otds_url: https://${local.otds_dns_name}/otdsws/login
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

`additionalGroupMemberships` allows to put pre-existing users or groups into existing OTDS groups. Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, each element consists of a `parent_group` value combined with either a `group_name` or `user_name` value depending whether you wannt to add a user or group.

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

`additionalAccessRoleMemberships` allows to put pre-existing users for groups into existing OTDS Access Roles.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, each element consists of a `access_role` value combined with either a `group_name`, `user_name`, or `partition_name` value depending whether you wannt to add a user, group, or a whole OTDS partition to the OTDS Access Role.

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

### Extended ECM Customizing Syntax

The payload syntax for Extended ECM configurations uses these lists (list elements are maps / dictionaries):

#### groups

`groups` is a list of Extended ECM user groups that are automatically created during the deployment.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, each group has a `name` and (optionally) a list of parent groups. `enable_o365`, `enable_salesforce`, and `enable_core_share` are used to control whether or not a Microsoft 365, Salesforce or Core Share group should be created matching the Extended ECM group. The example below shows two groups. The `Finance` group is a child group of the `Innovate` group. The `Finance` group is also created in Microsoft 365 if the variable `var.enable_o365` evaluates to `true`.

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

`users` is a list of Extended ECM users that are automatically created during deployment.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, users should have `name`, `password`, `firstname`, `lastname`, `email`, `title`, and `company`. The `password` of these users can also be randomly generated and can be printed by `terraform output -json` (all users have the same password). Each user need to have a base group that must be in the `groups` section of the payload. Optionally a user can have a list of additional groups. A user can also have a list of favorites. Favorites can either be the logical name of a workspace instance used in the payload (see workspace below) or it can be a nickname of an Extended item. Users can also have a **security clearance level** and multiple **supplementatal markings**. Both are optional. `security_clearance` is used to define the security clearance level of the user. This needs to match one of the existing security clearnace levels that have been defined in the `securityClearances`section in the payload. `supplemental_markings` defines a list of supplemental markings the user should get. These need to match markings defined in the `supplementalMarkings` section in the payload. The field `privileges` defines the standard privileges of a user. If it is omitted users get the default privileges `["Login", "Public Access"]`.

The customizing module is also able to automatically configure Microsoft 365 users for each Extended ECM user. To make this work, the Terraform variable for Office 365 / Microsoft 365 need to be configured. In particular `var.enable_o365` needs to be `true`. In the user settings `enable_o365` has to be set to `true` as well (or you use the variable `var.enable_o365` if the payload is in the `customization.tf` file). `m365_skus` defines a list of Microsoft 365 SKUs that should be assigned to the user. These are the technical SKU IDs that are documented by Microsoft: [Licensing Service Plans](https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference). Inside the `customizing.tf` file you also find a convinient map called `m365_skus` that map the SKU ID to readable names (such as "Microsoft 365 E3" or "Microsoft 365 E5"). The `enable_sap`, `enable_successfactors`, `enable_salesforce`, `enable_core_share` allow to automatically create + configure the users in connected SAP S/4HANA, SuccessFactors, Salesforce, and Core Share applications respectively.

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
        privileges            = ["Login", "Public Access"]        enable_o365           = var.enable_o365
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

`items` and `itemsPost` are lists of Extended ECM items such as folders, shortcuts or URLs that should be created automatically but are not included in transports. All items are created in the `Enterprise Workspace` of Extended ECM or any subfolder.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, each item needs to have `name` and `type` values. The parent ID of the item can either be specified by a nick name (`parent_nickname`) or by the path in the Enterprise Workspace (`parent_path`). The value `parent_path` is a list of folder names starting from the root level in the Enterprise Workspaces. `parent_path = ["Administration", "WebReports"]` creates the item in the `Websites` folder which is itself in the `Administration` top-level folder. The list `items` is processed at the beginning of the automation (before transports are applied) and `itemsPost` is applied at the end of the automation (after transports have been applied).

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
      enable: true
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

`permissions` and `permissionsPost` are both lists of Exteneded ECM items, each with a specific permission set that should be applied to the item.

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
        public_permissions = ["see", "see_content"]
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
      - see_content
      users:
      - name: '...'
        permissions: []
      volume: '...'
    ```

#### renamings

`renamings` is a list of Extended ECM items (e.g. volume names) that are automatically renamed during deployment.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable.

In addition, you have to either provide the `nodeid` (only a few node IDs are really know upfront such as 2000 for the Enterprise Workspace) or a `volume` (type ID). In case of volumes there's a list of known volume types defined at the beginning of the `customizing.tf` file with the variable `otcs_volumes`. You can also specific a description that will be used to update the description of the node / item.

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
        description = "Extended ECM Workspace and Document Templates"
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
    - description: Extended ECM Workspace and Document Templates
      enabled: true
      name: Content Server Document Templates
      volume: ${var.otcs_volumes["Content Server Document Templates"]}
    ```

#### adminSettings

`adminSettings` and `adminSettingsPost` are lists admin stettings that are applied before the transport packages (`adminSettings`) or directly after the transport packages (`adminSettingsPost`) in the customizing process.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, each setting is defined by a `description`, the `filename` of an XML file that includes the actual Extended ECM admin settings that are applied automatically (using XML import / LLConfig). These files need to be stored inside the `setting/payload` sub-folder inside the terraform folder.

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

#### externalSystems

`externalSystems` is a list of connections to external business applications such as SAP S/4HANA, Salesforce, or SuccessFactors. Some of the payload elements are common, some are specific for the type of the external system.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, the field `external_system_type` needs to have one of these values: `SAP`, `Salesforce`, `SuccessFactors`, `AppWorks Platform` or `Business Scenario Sample`. All other fields are dependent on the selection of the `type` value.

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

The `name` must be the exact file name of the ZIP package. Description is optional. Other than the `transportPackages` these transports are deployed **after** users and wrkspace instances have been processed. This allows to transport content into workspaces instances or use users inside thse transport packages (e.g. owners, user attributes, etc.)

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

#### workspaces

`workspaces` is a list of business workspaces instances that should be automatically created. Category, Roles, and Business Relationships can be provided.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, the `id` needs to be a unique value in the payload. It does not need to be something related to any of the actual Extended ECM workspace data. It is only used to establish relationship between different workspaces in the payload (using the list of IDs in `relationships`). **_Important_**: If the workspace type definition uses a pattern to generate the workspace name then the `name` in the payload should match the pattern in the workspace type definition. Otherwise incremental deployments of the payload may not find the existing workspaces and may try to recreate them resulting in an error. The `nickname` is the Extended ECM nickname that allows to refer to this item without knowing its technical ID.

Business Object information can be provided with a `business_objects` list. Each list item defines the external system (see above), the business object type, and business object ID. This list is optional.

Roles and membership information is provided with the `members` list. Each list item defines membership for a single workspace role which is defined with `role`. Members can be defined by two lists: `users` and `groups`. In the first example below the role `Sales Representative` is populated with user `nwheeler` and with the groups `Sales` and `Management`.

Classification information is optional and can be provided separately for Records Management classifications and normal/regular classifications. Both types of classifications need to be provided as pathes inside the respective classifications trees (top down). There can be only one Records Management classification but multiple regular classifications. That's why the element `classification_pathes` is a list of pathes.

Category information is provided in a list of blocks. Each block includes the category `name`, `set` name (optional, can be empty of the attribute is not in a set), `attribute` name, and the attribute `value`. Multi-value attributes are a comma-separated list of items in square brackets. The example below shows a customer workspace and a contract workspace that are related to each other (the customer workspace has an attribute `Sales Organization` that has multiple values: 1000 and 2000). The contract workspace has a multi-line attribute set. For multi-line attribute sets the payload needs an additional `row` value that specifies the row number in the multi-line set (starting with 1 for the first row).

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

`webReports` and `webReportsPost` are two lists of Extended ECM web reports that should be automatically executed during deployment. Having two lists give you the option to run some webReports after the business configuration and some others after demo content has been produced. These Web Reports have typically been deployd to Extended ECM system with the transport warehouse before. Each list item specifies one Web Report.

Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`).

In addition, the `nickname` is mandatory and defines the nickname of the Web Report to be executed. So you need to give each webReport you want to run a nickname before putting it in a transport package. The element `description` is optional. The `parameters` set defines parameter name and parameter value pairs. The corresponding Web Report in Extended ECM must have exactly these parameters defined.

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
        description = "Web Report to auto-configure Extended ECM for SuccessFactors Module Specific Settings"
      }
    ]

    webReportsPost = [
      {
        nickname    = "web_report_set_cust_sf"
        description = "Web Report to auto-configure Extended ECM for SuccessFactors Module Specific Settings"
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
    - description: Web Report to auto-configure Extended ECM for SuccessFactors Module
        Specific Settings
      nickname: web_report_set_cust_sf
    webReportsPost:
    - description: Web Report to auto-configure Extended ECM for SuccessFactors Module
        Specific Settings
      nickname: web_report_set_cust_sf
    ```

#### csApplications

`csApplications` is a list of Content Server Applications that should autmatically be deployed.

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

Each assignment assigns either a `workspace` or an Extended ECM item with a `nickname` to a defined list of `users` or `groups`. Assignments have a `subject` (title) and `instructions` for the target users or groups.

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

`documentGenerators` defines a list of document generators that is based on the document template capabilities of Extended ECM. Each element is a dictionary with these fields:

- `enabled` switch to turn payload element on or off (the default is `true`)
- `workspace_type` is the name of the workspace type. It is a mandatory field.
- `template_path` is a mandatory list for folder names (top-down). It is a mandatory information.
- `classification_path` is a mandatory list of classification elements (top-down)
- `category_name`is the name of the category (optional)
- `attributes` is a list of dictionaries containing the attribute information. The dictionary has keys `name` and `value`.
- `workspace_folder_path` (list, optional, default = []) - default puts the document in the workspace root
- `exec_as_user` is optional and defined the name (login ID) of the user. If not provided the document is generated with admin credentials.

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

#### workflowInitiations

`workflowInitiations` is a list of workflow initiations that starts workflows for each instance of a workspace type.
Each element is a dictionary with these fields:

- `enabled` switch to turn payload element on or off (the default is `true`)
- `worklow_nickname` is the nickname of the workflow (this is a mandatory field)
- `initiate_as_user` is the login name of the user that initiates the workflow
- `workspace_type` defines the name of the workspace type. For each instance of the given workspace type a workflow is started.
- `workspace_folder_path` defines the subfolder that contains the document(s) the workflow is started with (the documents are attched as links to the workspace instance)
- `title` is the title the workflow is started with
- `comment` is the comment the workflow initiator provides when starting the workflow.
- `due_in_days` is an integer value that defines the number of days the workflow is due (the due date is the start date plus the number of days specified with `due_in_days`)
- `attributes` is a list of dictionaries containing the attribute information. The dictionary has keys `name`, `value` and an optional `type`. Types can be `string`, `date`, `user`, and `integer`.

=== "Terraform / HCL"

    ```terraform
    workflowInitiations = [
      {
        enabled               = true
        workflow_nickname     = "wf_contract_approval_workflow"
        initiate_as_user      = "pwilliams"
        workspace_type        = "Purchase Contract"
        workspace_folder_path = ["01 - Contract"]
        title                 = "Contract Approval Workflow for Purchase Contracts"
        comment               = "Workflow initiated by Terrarium automation"
        due_in_days           = 4
        attributes = [
          {
            name  = "Approver"
            value = "dfoxhoven"
            type  = "User" # User, String, Integer, Boolean, Float, Date
          }
        ]
      },
      ...
    ]
    ```

### Bulk Load Customizing Syntax

For mass loading and generation of workspaces and documents from external data sources the customizing allows to specify bulk datasources, bulk workspaces, bulk workspace relationships and bulk documents. The data sources will be loaded in an internal table representation (we use Pandas Data Frames for this).

#### bulkDatasources

Before you can bulk load workspaces, workspace relationships, or documents you have to declare the used data sources. `bulkDatasources` is a list of datasources. Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`). First, a data source needs a `type`. Supported types are `excel` (Microsoft Excel workbooks), `servicenow` (ServiceNow REST API), `otmm` (OpenText Media Management REST API), `otcs` (Extended ECM REST API), `pht` (internal OpenText System for Product Master Data, REST API), `json` (JSON files), and `xml` (XML files, or whole directories / zip files of XML files). Based on the selected `type` data sources may have many specific fields to configure the specifics of the data source and define how to connect to the data source.

The following settings can be applied to all data source types:

- `cleansings` (dictionary, optional, default = {}) to clean the values in defined columns of the data set. Each list item is a dictionary with these keys:
    - `upper` (bool, optional, default = `false`)
    - `lower` (bool, optional, default = `false`)
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
- `columns_to_add_table` (list, optional, default = []): add a new column with table values. Each payload item is a dictionary with these keys:
    - `source_columns` (str, mandatory) - names of the columns from which row values are taken from to create a list of dictionary values. It is expected that the source columns already have list items or are strings with delimiter-separated values. 
    - `name` (str, mandatory) - name of the new column
    - `list_splitter` (str, optional, default = `,`) Defines the delimiter for splitting strings from the source columns into a list.
- `conditions` (list, optional, default = []) - each list item is a dict with these keys:
    - `field` (str, mandatory)
    - `value` (str | bool | list, optional, default = None)
- `explosions` (list, optional, default = []) - each list item is a dict with these keys:
    - `explode_fields` (str | list, mandatory)
    - `flatten_fields` (list, optional, default = `[]`)
    - `split_string_to_list` (bool, optional, default = False)
    - `list_splitter` (str, optional, default = `;,`) - defines the delimiters for splitting strings in a list.
- `name_column` (str, optional, default = None) - name of the column in the data source that determines the bulk item name
- `synonyms_column` (str, optional, default = None)

OpenText Extended ECM / Content Server specific settings (fields):

- `otcs_hostname` (str, mandatory)
- `otcs_protocol` (str, optional, default = `https`)
- `otcs_port` (str, optional, default = `443`)
- `otcs_basepath` (str, optional, default = `/cs/cs`)
- `otcs_username` (str, mandatory)
- `otcs_password` (str, mandatory)
- `otcs_thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `otcs_download_dir` (str, optional, default = `/data/contentserver`)
- `otcs_root_node_id` (int | list[int], mandatory)
- `otcs_filter_workspace_depth` (int, optional, default = 0) - 0 = workspaces are located immedeately below given root node
- `otcs_filter_workspace_subtypes` (list, optional, default = `[]`) - 0 = folder subtype
- `otcs_filter_workspace_category` (str, optional, default = None) - defines the category the workspace needs to have to pass the filter
- `otcs_filter_workspace_attributes` (dict | list, optional, default = None)
    - `set` (str, optional, default = None) - name of the attribute set
    - `row` (int, optional, default = None) - row number (starting with 1) - only required for multi-value sets
    - `attribute` (str, mandatory) - name of the attribute
    - `value` (str, mandatory) - value the attribute should have to pass the filter
- `otcs_filter_item_depth` (int, optional, default = None) - depth of the document under the given root
- `otcs_filter_item_category` (str, optional, default = None) - defines the category that the item needs to have to pass the filter
- `otcs_filter_item_attributes` (dict | list, optional, default = None)
    - `set` (str, optional, default = None) - name of the attribute set
    - `row` (int, optional, default = None) - row number (starting with 1) - only required for multi-value sets
    - `attribute` (str, mandatory) - name of the attribute
    - `value` (str, mandatory) - value the attribute should have to pass the filter

ServiceNow specific settings (fields):

- `sn_base_url` (str, mandatory)
- `sn_auth_type` (str, optional, default = `basic`)
- `sn_username` (str, optional, default = "")
- `sn_password` (str, optional, default = "")
- `sn_client_id` (str, optional, default = None)
- `sn_client_secret` (str, optional, default = None)
- `sn_table_name` (str, optional, default = `u_kb_template_technical_article_public`)
- `sn_queries` (list, mandatory)
    - `sn_table_name` (str, mandatory) - name of the ServiceNow database table for the query
    - `sn_query` (str, mandatory) - query string
- `sn_thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `sn_download_dir` (str, optional, default = `/data/knowledgebase`)

OpenText Media management specific settings (fields):

- `otmm_username` (str, optional, default = "")
- `otmm_password` (str, optional, default = "")
- `otmm_client_id` (str, optional, default = None)
- `otmm_client_secret` (str, optional, default = None)
- `otmm_thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `otmm_download_dir` (str, optional, default = `/data/mediaassets`)
- `otmm_business_unit_exclusions` (list, optional, default = `[]`)
- `otmm_product_exclusions` (list, optional, default = `[]`)

This is an example for bulkDatasources definitions:

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
              "-": " ",  # replace hypen with space
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

To bulk load workspaces you can define a payload section `bulkWorkspaces` which can produce a large number of workspaces based on placeholders that are filled with data from a defined datasource. Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`). First, a data source needs a `data_source` that specifies the name of a data source in the `bulkDatasources` payload section.

These are the settings in a single bulk workspace list element:

- `enabled` (bool, optional, default = `true`)
- `type_name` (str, mandatory) - type of the workspace
- `data_source` (str, mandatory) - name of a data source item defined in the `bulkDatasources`section.
- `force_reload` (bool, optional, default = `true`) - enforce a reload of the data source, e.g. useful if data source has been modified before by column operations or explosions
- `copy_data_source` (bool, optional, default = `false`) - to avoid sideeffects for repeative usage of the data source
- `operations` (list, optional, default = `["create"]`) - list of operations to apply for workspaces: `create`, `update`, `delete`, `recreate` (any combination of these). "recreate" = delete existing + create new
- `explosions` (list, optional, default = `[]`) - each list item is a dict with these keys:
    - `explode_fields` (str | list, mandatory)
    - `flatten_fields` (list, optional, default = `[]`)
    - `split_string_to_list` (bool, optional, default = `false`)
    - `list_splitter` (str, optional, default = `;,`) - defines the delimiters for splitting strings in a list.
- `unique` (list, optional, default = `[]`) - list of fields (columns) that should be unique -> deduplication
- `sort` (list, optional, default = `[]`) - list of fields to sort the data frame by
- `name` (str, mandatory)
- `description` (str, optional, default = "")
- `template_name` (str, optional, default = take first template)
- `categories` (list, optional, default = `[]`) - each list item is a dictionary that may have these keys:
    - `name` (str, mandatory)
    - `set` (str, default = "")
    - `row` (int, optional)
    - `attribute` (str, mandatory)
    - `value` (str, optional if value_field is specified, default = None)
    - `value_field` (str, optional if value is specified, default = None) - can include placeholder surrounded by {...}
    - `value_type` (str, optional, default = `string`) - possible values: `string`, `date`, `list` and `table`. If `list`is selected, then string with delimiter-separated values will be converted to a list.
    - `attribute_mapping` (dict, optional, default = None) - only relevant for value_type = "table" - defines a mapping from the data frame column names to the category attribute names
    - `list_splitter` (str, optional, default = `;,`) - only relevant for value_type `list`. Defines the delimiter for splitting strings in a list.
    - `lookup_data_source` (str, optional, default = None)
    - `lookup_data_failure_drop` (bool, optional, default = false) - should we clear / drop values that cannot be looked up?
    - `is_key` (bool, optional, default = false) - find workspace if name matching does not work (e.g. workspace name has changed in the data source since last run). For this we expect a `key` value to be defined in the bulk workspace and one of the category / attribute item to be marked with `is_key = true`.
- `external_create_date` (str, optional, default = "")
- `external_modify_date` (str, optional, default = "")
- `key` (str, optional, default = None) - lookup value for workspaces other then the name. Works in combination with `is_key` in the `categories` payload.
- `replacements` (dict, optional, default = `{}`) - Each dictionary item has the field name as the dictionary key and a list of regular expressions as dictionary value
 - `nickname` (str, optional, default = None)
 - `conditions` (list, optional, default = `[]`) - each list item is a dictionary that may have these keys:
    - `field` (str, mandatory)
    - `value` (str | bool | list, optional, default = None)
  - `aviator_metadata` (bool, optional, default = `false`) - Send request to feme to embedd the metadata for the workspace. Action will be performed after updates and creations.

This is an example for bulkWorkspaces definitions:

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

To bulk load workspace relationships you can define a payload section `bulkWorkspaceRelationships` which can produce a large number of workspace relationships based on placeholders that are filled with data from a defined datasource.

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
- `to_workspace` (str, mandatory) - nickname of the workspace on the _to_ side.
- `to_workspace_type` (str, optional, default = None) - type name of the workspace on the _from_ side.
- `to_workspace_name` (str, optional, default = None) - name of the workspace on the _from_ side.
- `to_workspace_data_source` (str, optional, default = None)
- `to_sub_workspace_name` (str, optional, default = None) - if the related workspace is a sub-workspace
- `to_sub_workspace_path` (list, optional, default = None) - the folder path under the main workspace where the sub-workspaces are located
- `type` (str, optional, default = `child`) - type of the relationship (defines if the _from_ workspace is the parent or the child)
- `data_source` (str, mandatory)
- `force_reload` (bool, optional, default = true) - enforce a reload of the data source, e.g. useful if data source has been modified before by column operations or explosions
- `copy_data_source` (bool, optional, default = false) - to avoid sideeffects for repeative usage of the data source
- `explosions` (list, optional, default = `[]`) - each list item is a dict with these keys:
    - `explode_fields` (str | list, mandatory)
    - `flatten_fields` (list, optional, default = `[]`)
    - `split_string_to_list` (bool, optional, default = false)
    - `list_splitter` (str, optional, default = `;,`) - defines the delimiters for splitting strings in a list.
- `unique` (list, optional, default = [])
- `sort` (list, optional, default = [])
- `thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `replacements` (list, optional, default = None)
- `conditions` (list, optional, default = None)
    - `field` (str, mandatory)
    - `value` (str | bool | list, optional, default = None)

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

To bulk load documents you can define a payload section `bulkDocuments` which can upload a large number of documents based on placeholders that are filled with data from a defined datasource. Each list element can include a switch called `enabled` to turn them on or off (the default is `true`). This switch can be controlled by a Terraform variable (or could just be `false` or `true`). First, a bulk document needs a `data_source` that specifies the name of a data source in the `bulkDatasources` payload section.

These are all the settings in a single bulk document list element:

- `enabled` (bool, optional, default = true)
- `data_source` (str, mandatory)
- `force_reload` (bool, optional, default = true) - enforce a reload of the data source, e.g. useful if data source has been modified before by column operations or explosions
- `copy_data_source` (bool, optional, default = false) - to avoid sideeffects for repeative usage of the data source
- `explosions` (list of dicts, optional, default = [])
    - `explode_fields` (str | list, mandatory)
    - `flatten_fields` (list, optional, default = [])
    - `split_string_to_list` (bool, optional, default = false)
    - `list_splitter` (str, optional, default = `;,`) - defines the delimiters for splitting strings in a list.
- `unique` (list, optional, default = []) - list of fields (columns) that should be unique -> deduplication
- `sort` (list, optional, default = []) - list of fields to sort the data frame by
- `operations` (list, optional, default = ["create"]) - possible values: `create`, `update`, `delete`, `recreate`
- `name` (str, mandatory) - can include placeholder surrounded by {...}
- `name_alt` (str, optional, default = None) - can include placeholder surrounded by {...}
- `description` (str, optional, default = None) - can include placeholder surrounded by {...}
- `download_name` (str, optional, default = name) - - can include placeholder surrounded by {...}
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
    - `value_type` (str, optional, default = `string`) - possible values: `string`, `date`, `list`, and `table`. If list then string with comma-separated values will be converted to a list.
    - `attribute_mapping` (dict, optional, default = None) - only relevant for value type `table` - defines a mapping from the data frame column names to the category attribute names
    - `list_splitter` (str, optional, default = `;,`) - only relevant for value type `list`. Defines the delimiter for splitting strings in a list.
    - `lookup_data_source` (str, optional, default = None)
    - `lookup_data_failure_drop` (bool, optional, default = false) - should we clear / drop values that cannot be looked up?
    - `is_key` (bool, optional, default = false) - find document is old name. For this we expect a `key` value to be defined for the bulk document and one of the category / attribute item to be marked with `is_key = true`.
- `thread_number` (int, optional, default = BULK_THREAD_NUMBER)
- `external_create_date` (str, optional, default = "")
- `external_modify_date` (str, optional, default = "")
- `key` (str, optional, default = None) - lookup key for documents other then the name
- `download_wait_time` (int, optional, default = 30)
- `download_retries` (int, optional, default = 2)
- `replacements` (list, optional, default = `[]`)
- `conditions` (list, optional, default = `[]`) - all conditions must evaluate to true
    - `field` (str, mandatory)
    - `value` (str | bool | list, optional, default = None)
- `workspaces` (list, optional, default = `[]`) - the workspaces the document should be uploaded to
    - `workspace_name` (str, mandatory)
    - `conditions` (list, optional, default = `[]`)
        - `field` (str, mandatory)
        - `value` (str | bool | list, optional, default = None)
    - `workspace_type` (str, mandatory)
    - `datasource` (str, optional, default = None)
    - `workspace_folder` (str, optional, default = "")
    - `workspace_path` (list, optional, default = `[]`)
    - `sub_workspace_type` (str, optional, default = "")
    - `sub_workspace_name` (str, optional, default = "")
    - `sub_workspace_template` (str, optional, default = "")
    - `sub_workspace_folder` (str, optional, default = "")
    - `sub_workspace_path` (list, optional, default = `[]`)


This is an example for bulkWorkspaceRelationships definitions:

=== "Terraform / HCL"

    ```terraform
    bulkDocuments = [
      {
        data_source        = "ntsb"
        download_url       = "https://data.ntsb.gov/carol-repgen/api/Aviation/ReportMain/GenerateNewestReport/{cm_mkey}/pdf"
        download_dir       = "/data/ntsb/incident-reports/"
        name               = "{cm_ntsbNum}"
        file_extension     = "pdf"
        mime_type          = "application/pdf"
        download_name      = "{cm_mkey}"
        delete_download    = false
        download_retries   = 2
        download_wait_time = 5 # wait to before retry in seconds
        conditions         = [
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

### Advanced Customizing Syntax

For advanced use cases that are not covered by Extended ECM or OTDS APIs, there are additional customizing capabilities.
This includes calling SAP Remote Function Calls (RFC), executing commands in the Kubernetes Pods or triggering web hooks (HTTP POST requests):

#### execPodCommands

`execPodCommands` is used to execute a Linux command inside a Kubernetes pod using the Kubernetes API (similar to what `kubectl exec` does). This may be handy to influence / change some of the intrinsics of the pods. If `eanbled` evaluates to `true` then the command will be called during the customization process. The `pod_name` must match is technical name of the pod in the Kubernetes deployment (you can get the pod names with `kubectl get pods`). `command` is a list of the command terms and parameters. The first element is typically the Linux shell that is used for executing the command and the second parameter is typically `-c` if the command is run in non-interactive mode. `interactive` defines if the command is run interactively or not. The default is to run the command non-interactively. Only for longer running commands you should prefer to run the command interactively.

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

#### webHooks

`webHooks` and `webHooksPost` are used to call (HTTP request) defined URLs that may trigger certain activities as webhooks. `webHooks` is called at the beginning of the customization process and `webHooksPost` is called at the end.

If `eanbled` evaluates to `true` then the weekhook is active.

`url` defines the URL of the web hook. `method` can we one of the typical HTTP request types (POST, GET, PUT, ...). If it is omitted the default is `POST`. `description` should describe the purpose of the web hook. The parameters `payload` and `headers` are maps (dictionaries) of name, value pairs. These are passed as additional header or body values to the HTTP request.

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

`sapRFCs` are defining a list of SAP Remote Function Calls (RFC) that are called to automate things in SAP S/4HANA. If `eanbled` evaluates to `true` then the RFC will be called during the customization process. `name` is the technical SAP name of the RFC. `description` is optional and is just informative. If the RFC requires parameters they can be passed via the `parameters` block (name, value pairs).

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

---

### Search Aviator Customizing Syntax

#### avtsRepositories

`avtsRepositories` is used to define Search Aviator repositories.

These are all the settings in a single repository list element:

- `enabled`: true/false
- `name`: Name of the Repository needs to be unique
- `type`: AVTS repository type:
    - Extended ECM
    - Documentum

##### Extended ECM specific values

- `otcs_url`: URL of Content Server (OTCS) https://otcs.domain.tld/cs/cs
- `otcs_api_url`: URL of Content Server (OTCS) https://otcs.domain.tld/cs/cs
- `username`: Username for Content Server crawling
- `password`: Passoword for the crawling user
- `node_id`: Node ID of the Content Server root folder

##### Documentum specific values

`to be done`

=== "Terraform / HCL"

    ```terraform
      avtsRepositories = [
        {
          enabled  = true
          name     = "Extended ECM"
          type     = "Extended ECM"
          otcs_url = "https://otcs.domain.tld/cs/cs"
          otcs_url = "http://otcs-frontend/cs/cs"
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

---

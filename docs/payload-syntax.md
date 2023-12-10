# Payload Syntax

## Customizing

The customizing payload can be defined in either of the following standards:

- [Terraform / HCL](https://developer.hashicorp.com/terraform/language/expressions/types)
- [YAML](https://yaml.org/spec/1.2.2/)

=== "Terraform / HCL"

    The Terraform language uses the following types for its values:

    - `string`: a sequence of Unicode characters representing some text, like `"hello"`.
    - `number`: a numeric value. The number type can represent both whole numbers like 15 and fractional values like `6.283185`.
    - `bool`: a boolean value, either true or false. bool values can be used in conditional logic.
    - `list (or tuple)`: a sequence of values, like `["user1", "user2"]`.
    - `map (or dictionary)`: a group of values identified by named labels, like `{name = "nwheeler", security_clearance = 50}`.

    Most of the customizing settings may have an optional field called `enabled` that allows to dynamically turn on / off customization settings based on a boolean value that may be read from a Terraform variable (or could just be `False` or `True`). In case you are using additional external payload (see above) you need to provide `False` or `True` directly. If `enabled` is not specified then `enabled = True` is assumed (this is the default).

=== "YAML"

    The YAML language uses the following types for its values:

    - `string`: a sequence of Unicode characters representing some text, like `hello`.
    - `number`: a numeric value. The number type can represent both whole numbers like 15 and fractional values like `6.283185`.
    - `bool`: a boolean value, either `True` or `False`.
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

#### partitions

`partitions` allows to create new partitions in OTDS. It is also possible to directly put the new partition into an existing `access role`:

=== "Terraform / HCL"

    ```terraform
    partitions = [
      {
          name        = "Salesforce"
          description = "Salesforce user partition"
          synced      = false
          access_role = "Access to cs"
      }
    ]
    ```

=== "YAML"

    ```yaml
    partitions:
      - name: "Salesforce"
        description: "Salesforce user partition"
        synced: False
        access_role: "Access to cs"
    ```

#### oauthClients

`oauthClients` allows to create new OAuth client in OTDS. Each list element includes a switch `enabled` to turn them on or off. This switch can be controlled by a Terraform variable. `name` defines the name of the OTDS OAuth client and `description` should describe what the OAuth client is used for. Each OAuth client has the typical elements such as `confidential`, OTDS `partition`, a `redirect_url`, `permission_scope`, `default_scope`, and `allow_impersonation`.

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
    ```

#### authHandlers

`authHandlers` is a list of additional OTDS authentication handlers. The values can also use terraform variables.

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
        token_endpoint: '...'
        type: '...'
    ```

#### trustedSites

`trustedSites` allows you to define trusted sites for OTDS. Each trusted site defines a URL and can be enabled or disabled. Regular expressions are allowed to define patterns.

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

`systemAttributes` allows you to set system attributes in OTDS. Each trusted site has a name, value and an optional description.

=== "Terraform / HCL"

    ```terraform
    systemAttributes = [
      {
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
      name: otds.as.SameSiteCookieVal
      value: None
    ```

#### additionalGroupMemberships

`additionalGroupMemberships` allows to put a pre-existing users or groups into existing OTDS groups. Each element consists of a `parent_group` value combined with either a `group_name` or `user_name` value depending whether you wannt to add a user or group.

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

`additionalAccessRoleMemberships` allows to put pre-existing users for groups into existing OTDS Access Roles. Each element consists of a `access_role` value combined with either a `group_name`, `user_name`, or `partition_name` value depending whether you wannt to add a user, group, or a whole OTDS partition to the OTDS Access Role.

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

The payload syntax for Extended ECM configurations uses these lists (most elements are maps, some are plain strings):

#### groups

`groups` is a list of Extended ECM user groups that are automatically created during the deployment. Each group has a name and (optionally) a list of parent groups. The switch `enabled` is used to turn groups on or off. This switch can be controlled by a Terraform variable. `enable_o365` is used to control whether or not a Microsoft 365 group should be created matching the Extended ECM group. The example below shows two groups. The `Finance` group is a child group of the `Innovate` group. The `Finance` group is also created in Microsoft 365 if the variable `var.enable_o365` evaluates to `true`.

=== "Terraform / HCL"

    ```terraform
    groups = [
      {
        name          = "Innovate"
        parent_groups = []
      },
      {
        name          = "Finance"
        parent_groups = ["Innovate"]
        enable_o365   = var.enable_o365
      }
    ]
    ```

=== "YAML"

    ```yaml
    groups:
    - name: Innovate
      parent_groups: []
    - enable_o365: ${var.enable_o365}
      name: Finance
      parent_groups:
      - Innovate
    ```

#### users

`users` is a list of Extended ECM users that are automatically created during deployment. The password of these users is randomly generated and can be printed by `terraform output -json` (all users have the same password). Each user need to have a base group that must be in the `groups` section of the payload. Optionally a user can have a list of additional groups. A user can also have a list of favorites. Favorites can either be the logical name of a workspace instance used in the payload (see workspace below) or it can be a nickname of an Extended item. Users can also have a **security clearance level** and multiple **supplementatal markings**. Both are optional. `security_clearance` is used to define the security clearance level of the user. This needs to match one of the existing security clearnace levels that have been defined in the `securityClearances`section in the payload. `supplemental_markings` defines a list of supplemental markings the user should get. These need to match markings defined in the `supplementalMarkings` section in the payload. The field `privileges` defines the standard privileges of a user. If it is omitted users get the default privileges `["Login", "Public Access"]`. The customizing module is also able to automatically configure Microsoft 365 users for each Extended ECM user. To make this work, the Terraform variable for Office 365 / Microsoft 365 need to be configured. In particular `var.enable_o365` needs to be `true`. In the user settings `enable_o365` has to be set to `true` as well (or you use the variable `var.enable_o365` if the payload is in the `customization.tf` file). `m365_skus` defines a list of Microsoft 365 SKUs that should be assigned to the user. These are the technical SKU IDs that are documented by Microsoft: [Licensing Service Plans](https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference). Inside the `customizing.tf` file you also find a convinient map called `m365_skus` that map the SKU ID to readable names (such as "Microsoft 365 E3" or "Microsoft 365 E5").

=== "Terraform / HCL"

    ```terraform
    users = [
      {
        name                  = "adminton"
        password              = local.password
        firstname             = "Adam"
        lastname              = "Minton"
        email                 = "adminton@innovate.com"
        base_group            = "Administration"
        groups                = ["IT"]
        favorites             = ["workspace-a", "nickname-a"]
        security_clearance    = 50
        supplemental_markings = ["EUZONE"]
        privileges            = ["Login", "Public Access", "Content Manager", "Modify Users", "Modify Groups", "User Admin Rights", "Grant Discovery", "System Admin Rights"]
        enable_o365           = var.enable_o365
        m365_skus             = [var.m365_skus["Microsoft 365 E3"]]
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
        base_group            = "Sales"
        groups                = ["Manager", "Office365"]
        favorites             = ["workspace-b", "nickname-b"]
        security_clearance    = 95
        supplemental_markings = ["EU-GDPR-PD", "EUZONE"]
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
    - base_group: Sales
      email: nwheeler@innovate.com
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
      security_clearance: 95
      supplemental_markings:
      - EU-GDPR-PD
      - EUZONE
    ```

#### items

`items` and `itemsPost` are lists of Extended ECM items such as folders, shortcuts or URLs that should be created automatically but are not included in transports. All items are created in the `Enterprise Workspace` of Extended ECM or any subfolder. Each item needs to have `name` and `type` values. The parent ID of the item can either be specified by a nick name (`parent_nickname`) or by the path in the Enterprise Workspace (`parent_path`). The value `parent_path` is a list of folder names starting from the root level in the Enterprise Workspaces. `parent_path = ["Administration", "WebReports"]` creates the item in the `Websites` folder which is itself in the `Administration` top-level folder. The list `items` is processed at the beginning of the automation (before transports are applied) and `itemsPost` is applied at the end of the automation (after transports have been applied).

=== "Terraform / HCL"

    ```terraform
    items = [
        {
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

`permissions` and `permissionsPost` are both lists of Exteneded ECM items, each with a specific permission set that should be applied to the item. The item can be specified via a path (list of folder names in Enterprise workspace in top-down order), via a nickname, or via a volume. Permission values are listed as list strings in `[...]` for `owner_permissions`, `owner_group_permissions`, or `public_permissions`. They can be a combination of the following values: `see`, `see_contents`, `modify`, `edit_attributes`, `add_items`, `reserve`, `add_major_version`, `delete_versions`, `delete`, and `edit_permissions`. The `apply_to` specifies if the permissions should only be applied to the item itself (value 0) or only to sub-items (value 1) or the item _and_ its sub-items (value 2). The list specified by `permissions` is applied _before_ the transport packages are applied and `permissionsPost` is applied _after_ the transport packages have been processed.

=== "Terraform / HCL"

    ```terraform
    permissions = [
      {
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

`renamings` is a list of Extended ECM items (e.g. volume names) that are automatically renamed during deployment. You have to either provide the `nodeid` (only a few node IDs are really know upfront such as 2000 for the Enterprise Workspace) or a `volume` (type ID). In case of volumes there's a list of known volume types defined at the beginning of the `customizing.tf` file with the variable `otcs_volumes`. You can also specific a description that will be used to update the description of the node / item.

=== "Terraform / HCL"

    ```terraform
    renamings = [
      {
        nodeid      = 2000
        name        = "Innovate"
        description = "Innovate's Enterprise Workspace"
      },
      {
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
      name: Innovate
      nodeid: 2000
    - description: Extended ECM Workspace and Document Templates
      name: Content Server Document Templates
      volume: ${var.otcs_volumes["Content Server Document Templates"]}
    ```

#### adminSettings

`adminSettings` and `adminSettingsPost` are lists admin stettings that are applied before the transport packages (`adminSettings`) or directly after the transport packages (`adminSettingsPost`) in the customizing process. Each setting is defined by a `description`, the `filename` of an XML file that includes the actual Extended ECM admin settings that are applied automatically (using XML import / LLConfig). These files need to be stored inside the `setting/payload` sub-folder inside the terraform folder.
Each admin setting may have a field called `enabled` that allows to dyanmically turn on / off admin settings based on a boolean value that may be read from a Terraform variable (or could just be `False` or `True`).

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

`externalSystems` is a list of connections to external business applications such as SAP S/4HANA, Salesforce, or SuccessFactors. Some of the fields are common, some are specific for the type of the external system.
Each external system has a field called `enabled` that allows to dyanmically turn on / off external system configurations based on a boolean value that may be read from a Terraform variable (or could just be `False` or `True`). The field `external_system_type` needs to have one of these values: `SAP`, `Salesforce`, `SuccessFactors`, or `AppWorks Platform`.

=== "Terraform / HCL"

    ```terraform
    externalSystems = [
      {
        enabled              = var.enable_sap
        external_system_type = "SAP"
        external_system_name = "TM6"
        description          = "SAP S/4HANA on-premise"
        as_url               = "https://tmcerp1.eimdemo.biz:8443/sap/bc/srt/xip/otx/ecmlinkservice/100/ecmlinkspiservice/basicauthbinding"
        base_url             = "https://tmcerp1.eimdemo.biz:8443"
        username             = "demo"
        password             = local.password
        certificate_file     = "/certificates/TM6.pse"
        certificate_password = "topsecret"
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
    - as_url: https://tmcerp1.eimdemo.biz:8443/sap/bc/srt/xip/otx/ecmlinkservice/100/ecmlinkspiservice/basicauthbinding
      base_url: https://tmcerp1.eimdemo.biz:8443
      certificate_file: /certificates/TM6.pse
      certificate_password: topsecret
      description: SAP S/4HANA on-premise
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

`transportPackages` is a list of transport packages that should be applied automatically. These packages need to be accessible via the provided URLs. The `name` must be the exact file name of the ZIP package. Description is optional.

=== "Terraform / HCL"

    ```terraform
    transportPackages = [
        {
          url         = "https://terrarium.blob.core.windows.net/transports/Terrarium-010-Categories.zip"
          name        = "Terrarium 010 Categories.zip"
          description = "Terrarium Category definitions"
        },
        {
          url         = "https://terrarium.blob.core.windows.net/transports/Terrarium-020-Classifications.zip"
          name        = "Terrarium 20 Classifications.zip"
          description = "Terrarium Classification definitions"
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

`contentTransportPackages` is a list of content transport packages that should be automatically applied. Content Transport Package typically are used to import documents into workspaces that are created before. These packages need to be accessible via the provided URLs. The `name` must be the exact file name of the ZIP package. Description is optional. Other than the `transportPackages` these transports are deployed **after** users and wrkspace instances have been processed. This allows to transport content into workspaces instances or use users inside thse transport packages (e.g. owners, user attributes, etc.)

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

`workspaces` is a list of business workspaces instances that should be automatically created. Category, Roles, and Business Relationships can be provided. The `id` needs to be a unique value in the payload. It does not need to be something related to any of the actual Extended ECM workspace data. It is only used to establish relationship between different workspaces in the payload (using the list of IDs in `relationships`). **_Important_**: If the workspace type definition uses a pattern to generate the workspace name then the `name` in the payload should match the pattern in the workspace definition. Otherwise incremental deployments of the payload may not find the existing workspaces and may try to recreate them resulting in an error.

Business Object information can be provided with a `business_objects` list. Each list item defines the external system (see above), the business object type, and business object ID. This list is optional.

Roles and membership information is provided with the `members` list. Each list item defines membership for a single workspace role which is defined with `role`. Members can be defined by two lists: `users` and `groups`. In the first example below the role `Sales Representative` is populated with user `nwheeler` and with the groups `Sales` and `Management`.

Classification information is optional and can be provided separately for Records Management classifications and normal/regular classifications. Both types of classifications need to be provided as pathes inside the respective classifications trees (top down). There can be only one Records Management classification but multiple regular classifications. That's why the element `classification_pathes` is a list of pathes.

Category information is provided in a list of blocks. Each block includes the category `name`, `set` name (optional, can be empty of the attribute is not in a set), `attribute` name, and the attribute `value`. Multi-value attributes are a comma-separated list of items in square brackets. The example below shows a customer workspace and a contract workspace that are related to each other (the customer workspace has an attribute `Sales Organization` that has multiple values: 1000 and 2000). The contract workspace has a multi-line attribute set. For multi-line attribute sets the payload needs an additional `row` value that specifies the row number in the multi-line set (starting with 1 for the first row).

A thrid workspace in the example below is for `Material` - it has an additional field called `template_name` which is optional. It can be used if there are multiple templates for one workspace type. If it is not specified and the workspace type has multiple workspace templates the first template is automatically selected.

=== "Terraform / HCL"

    ```terraform
    workspaces = [
      {
        id          = "50031"
        name        = "Global Trade AG (50031)"
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

`webReports` and `webReportsPost` are two lists of Extended ECM web reports that should be automatically executed during deployment. Having two lists give you the option to run some webReports after the business configuration and some others after demo content has been produced. These Web Reports have typically been deployd to Extended ECM system with the transport warehouse before. Each list item specifies one Web Report. The `nickname` is mandatory and defines the nickname of the Web Report to be executed. So you need to give each webReport you want to run a nickname before putting it in a transport package. The element `description` is optional. The `parameters` set defines parameter name and parameter value pairs. The corresponding Web Report in Extended ECM must have exactly these parameters defined.

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

`csApplications` is a list of Content Server Applications that should autmatically be deployed. Each element has a `name` for the application and optionally a `description`.

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

`assignments` is a list of assignments. Assignments are typically used for _Extended ECM for Government_. Each assignment assigns either a `workspace` or an Extended ECM item with a `nickname` to a defined list of `users` or `groups`. Assignments have a `subject` (title) and `instructions` for the target users or groups.

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

#### workspaceTemplateRegistrations

`workspaceTemplateRegistrations` is used to register certain workspace templates for the use as projects in _Extended ECM for Engineering_ demo scenarios. Each registration has two mandatory fields. `workspace_type_name` defines the name of the workspace type and `workspace_template_name` defines the specific name of the workspace templates (as each workspace type may have multiple templates).

=== "Terraform / HCL"

    ```terraform
      workspaceTemplateRegistrations = [
        {
          workspace_type_name     = "SAP PPM Project"
          workspace_template_name = "Project"
        }
      ]
    ```

=== "YAML"

    ```yaml
    workspaceTemplateRegistrations:
    - workspace_template_name: Project
      workspace_type_name: SAP PPM Project
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

`webHooks` and `webHooksPost` are used to call (HTTP request) defined URLs that may trigger certain activities as webhooks. `webHooks` is called at the beginning of the customization process and `webHooksPost` is called at the end. If `eanbled` evaluates to `true` then the weekhook is active. `url` defines the URL of the web hook. `method` can we one of the typical HTTP request types (POST, GET, PUT, ...). If it is omitted the default is `POST`. `description` should describe the purpose of the web hook. The parameters `payload` and `headers` are maps (dictionaries) of name, value pairs. These are passed as additional header or body values to the HTTP request.

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

##################################################################
# Query Calm App Detail 
##################################################################

Function REST-Get-Calm-App-Detail {
<#
.SYNOPSIS
Gets the detailed status for a calm App.

.DESCRIPTION
API responds even if in deleted state.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.PARAMETER UUID
UUID of the calm app.

.EXAMPLE

REST-Get-Calm-App-Detail -PcClusterIP xxx -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -UUID de9d5b96-b0f1-4f2d-8a13-3873ba4e9f0f
'21-Jul-21 07:35:14' | INFO  | Query Calm App 'de9d5b96-b0f1-4f2d-8a13-3873ba4e9f0f'

status
------
@{active_app_profile_instance_reference=; protection_status=; description=This Marketplace is running against branch 'master'…

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [String] $Uuid
  )

  write-log -message "Query Calm App '$UUID'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/$($UUID)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Query Calm Apps No Filter Do not use. 
##################################################################

Function REST-Query-Calm-Apps {
<#
.SYNOPSIS
Gets the Apps List in Calm.

.DESCRIPTION
API responds even if in deleted state.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.EXAMPLE
REST-Query-Calm-Apps -PcClusterIP xxx -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead
'21-Jul-21 07:35:14' | INFO  | Query Calm App 'de9d5b96-b0f1-4f2d-8a13-3873ba4e9f0f'

status
------
@{active_app_profile_instance_reference=; protection_status=; description=This Marketplace is running against branch 'master'…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload= @{
    kind="app"
    offset=0
    length=5000
  } 
  write-log -message "Query Calm Apps List"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/list"
    Method      = "Post"
    Body        = $PsHashPayload 
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Query Calm Apps App Name Filter
##################################################################

Function REST-Query-Calm-Apps-FilterName {
<#
.SYNOPSIS
Gets the Apps List in Calm filters on name.

.DESCRIPTION
Suitable for 429 responses, Calm Apps List Based on filtername, undeleted apps.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.PARAMETER FilterName
FilterName the string value to filter Apps on.

.EXAMPLE
REST-Query-Calm-Apps-FilterName `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Filter "^Control Panel"
'30-Dec-21 12:18:14' | INFO  | Query Calm Apps List
'30-Dec-21 12:18:14' | INFO  | Converting Object
'30-Dec-21 12:18:15' | INFO  | We found '2' items.

Name                           Value
----                           -----
api_version                    3.0
entities                       {@{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}}
metadata                       {offset, total_matches, kind, length}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $Filter
  )

  $PsHashPayload= @{
    filter="name==.*$($Filter).*;_state!=deleted"
    kind="app"
    offset=0
    length=250
  } 

  write-log -message "Query Calm Apps List"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/list"
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Query Calm Apps App Name Filter
##################################################################

Function REST-Query-Calm-Apps-FilterProject {
<#
.SYNOPSIS
Gets the Apps List in Calm filters on name.

.DESCRIPTION
Suitable for 429 responses, Calm Apps List Based on Project UUID.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.PARAMETER ProjectUuid
ProjectUuid UUID of the project to filter on..

.EXAMPLE
REST-Query-Calm-Apps-FilterProject `
  -PCClusterIP $MainVars.AutoDC.PCClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ProjectUuid $project.metadata.uuid
'31-Jul-21 23:04:10' | INFO  | Query Calm Apps, Filtering on Project UUID: 'f4aaca45-6c94-4301-84c4-bbe208e545d1'
'31-Jul-21 23:04:10' | INFO  | Query Calm Apps List

api_version metadata                     entities
----------- --------                     --------
3.0         @{total_matches=1; kind=app} {@{status=; spec=; api_version=3.0; metadata=}}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ProjectUuid
  )

  write-log -message "Query Calm Apps, Filtering on Project UUID: '$ProjectUuid'"

  $PsHashPayload = @{
    advanced_filter = @{
      project_reference_list = [array]$(
        "$ProjectUuid"
      )
    }
    kind   = "app"
    offset = 0
    length = 99 ## max Value
  } 
  write-log -message "Query Calm Apps List"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/list"
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Query PC Projects No Filter, deprecated.
##################################################################

Function REST-Query-Pc-Projects {
<#
.SYNOPSIS
Gets the Projects list in Prism Central

.DESCRIPTION
Suitable for 429 responses

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.EXAMPLE
Rest-Query-Pc-Projects `
  -PCClusterIP $MainVars.AutoDC.PCClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'31-Jul-21 23:08:31' | INFO  | Query Pc Projects
'31-Jul-21 23:08:31' | INFO  | Please Depricate this function

api_version metadata                                               entities
----------- --------                                               --------
3.1         @{total_matches=11; kind=project; length=11; offset=0} {@{status=; spec=; metadata=}, @{status=; spec=; me…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Query Pc Projects"
  write-log -message "Please Deprecate this function" -d 2

  $PsHashPayload= @{
    kind="project"
    offset=0
    length=9990
  } 

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/projects/list"
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Query PC Projects FilterName
##################################################################

Function REST-Query-Pc-Projects-FilterName {
<#
.SYNOPSIS
Gets the Projects list in Prism Central, Filters on Name, Contains.

.DESCRIPTION
Pagination Supported.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.PARAMETER Filter
Filter string value to filter on, contains.

.EXAMPLE
Rest-Query-Pc-Projects-FilterName `
  -PCClusterIP $MainVars.AutoDC.PCClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead -filter "RETSE124"
'31-Jul-21 23:16:42' | INFO  | Query Pc Projects
'31-Jul-21 23:16:42' | INFO  | Please Depricate this function

api_version metadata                                                                        entities
----------- --------                                                                        --------
3.1         @{filter=name==.*RETSE124.*; total_matches=2; kind=project; length=2; offset=0} {@{status=; spec=; metadat…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $Filter
  )

  write-log -message "Query Pc Projects, using Filter: '$Filter'"

  $PsHashPayload= @{
    kind="project"
    offset=0
    length=250
    filter="name==.*$($Filter).*"
  } 

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/projects/list"
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Get PC Project Detailed
##################################################################

Function REST-Get-Pc-Project-Detail {
<#
.SYNOPSIS
Gets the Project detail in Prism Central, Requires Project object as input

.DESCRIPTION
Pulls the detailed project object from Prism Central Projects
Projects are Prism Central related only. 
Requires the Project UUID to pull.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.PARAMETER ProjectUuid
Use REST-Query-Pc-Projects-FilterName as input uuid.

.EXAMPLE
REST-Get-Pc-Project-Detail -PcClusterIP xxx -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -ProjectUuid $project.metadata.uuid
'31-Jul-21 23:47:24' | INFO  | Getting Detailed Project 'fb8f2fd7-154d-46b0-947a-402ceea34b22'

status                                                                                                    spec
------                                                                                                    ----
@{state=COMPLETE; access_control_policy_list_status=System.Object[]; project_status=; execution_context=} @{access_con…
#>

  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $ProjectUuid
  )

  write-log -message "Getting Detailed Project '$($ProjectUuid)'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/projects_internal/$($ProjectUuid)"
    Method      = "Get"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Create Calm Environment.
##################################################################

Function REST-Add-Calm-Environment {
<#
.SYNOPSIS
Creates an Environment for a project. This is a cross reference component.
Project also needs to be patched (put) with the new environment

.DESCRIPTION
Suitable for 429 responses

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.PARAMETER ProjectObj
ProjectObj Use REST-Query-Pc-Projects-FilterName as input object, without entity structure.

.PARAMETER EnvironmentName
Name of the environment object to be created.

.PARAMETER SubnetUuid
Subnet uuid of the subnet that needs to be added to this environment

.PARAMETER AccountUuid
Uuid of the account that needs to be added to the environment.

.EXAMPLE

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $ProjectObj,
    [parameter(mandatory)] [string] $EnvironmentName,
    [parameter(mandatory)] [string] $SubnetUuid,
    [parameter(mandatory)] [string] $AccountUuid

  )

  $PsHashPayload = @{
    api_version = "3.0"
    metadata = @{
      kind = "environment"
      project_reference = @{
        kind = "project"
        name = $ProjectObj.status.name
        uuid = $ProjectObj.metadata.uuid
      }
      uuid = (new-guid).guid
    }
    spec =@{
      name = $EnvironmentName
      description = ""
      resources = @{
        substrate_definition_list = [array]@()
        credential_definition_list = [array]@()
        infra_inclusion_list = [array]@(@{
          account_reference= @{
            uuid = $AccountUuid
            kind = "account"
          }
          type = "nutanix_pc"
          subnet_references = [array]@(@{
            uuid = $SubnetUuid
          })
          default_subnet_reference = @{
            uuid = $SubnetUuid 
          } 
        })
      }
    }
  } 

  write-log -message "Creating Environment      : '$($PsHashPayload.metadata.uuid)'"
  write-log -message "Using Account Uuid        : '$AccountUuid'"
  write-log -message "Using Subnet Uuid         : '$SubnetUuid'"
  write-log -message "Project Uuid              : '$($ProjectObj.metadata.uuid)'"
  write-log -message "Project Name              : '$($ProjectObj.status.name)'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/environments"
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Query PC Accounts
##################################################################

Function REST-Query-Calm-Accounts {
<#
.SYNOPSIS
Gets the Calm Accounts in Prism Central

.DESCRIPTION
Accounts are Pe Providers in Calm

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.EXAMPLE
REST-Query-Calm-Accounts -PcClusterIP xxx -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead
'01-Aug-21 14:36:56' | INFO  | Listing Account / Provider

api_version metadata                         entities
----------- --------                         --------
3.0         @{total_matches=6; kind=account} {@{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_ver…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Listing Account / Provider"

  $PsHashPayload= @{
    offset=0
    length=250
  } 

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/accounts/list" 
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Update the project object through Calm API
##################################################################

Function REST-Update-Calm-Project-Object {
<#
.SYNOPSIS
Sends the project detail input object back to Calm for updating.

.DESCRIPTION
This is a generic update function for Calm Projects. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER ProjectDetail
Detailed Project object as input is required.

.EXAMPLE

#>

  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $ProjectDetail
  )

  write-log -message "Updating Project '$($ProjectDetail.metadata.uuid)' Object"
  write-log -message "Stripping 'Status'" -d 2 

  $ProjectDetail.psobject.members.remove("Status")

  write-log -message "Setting ACP to 'UPDATE'" -d 2

  $ProjectDetail.spec.access_control_policy_list | % {
    $_ | add-member noteproperty operation "UPDATE"
  }

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_projects/$($ProjectDetail.metadata.uuid)"
    Method      = "PUT"
    Body        = $ProjectDetail
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Calm Enviroment Detailed
##################################################################

Function REST-Get-Calm-Environment-Detail {
<#
.SYNOPSIS
Gets the environment detailed object.

.DESCRIPTION
Pulls the environment detailed object.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.EXAMPLE
REST-Get-Calm-Environment-Detail -PcClusterIP 10.230.88.27 -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -EnvironmentUuid $uuid
'30-Dec-21 12:25:35' | INFO  | Getting Environment: 'eda25533-0faa-4c45-8300-55b9bf843c81' Object
'30-Dec-21 12:25:35' | INFO  | Stripping 'Status'

status                                                                                                                                                          spec
------                                                                                                                                                          ----
@{description=; uuid=eda25533-0faa-4c45-8300-55b9bf843c81; state=ACTIVE; message_list=System.Object[]; resources=; name=Environment-RETSE124-NXC000_Networking} @{name=Environm…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $EnvironmentUuid
  )

  write-log -message "Getting Environment: '$($EnvironmentUuid)' Object"
  write-log -message "Stripping 'Status'" -d 2 

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/environments/$($EnvironmentUuid)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Delete PC Project 
##################################################################

Function REST-Delete-Calm-Project {
<#
.SYNOPSIS
Deletes in Prism Central Projects, Requires Project object as input

.DESCRIPTION
Suitable for 429 responses

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER ProjectUuid
ProjectObj Use Query-Pc-Project-Filtername as input UUID.

.EXAMPLE
 PS C:\Program Files\PowerShell\7> REST-Delete-Pc-Project -PcClusterIP xxx -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -ProjectUuid $project.metadata.uuid
'31-Jul-21 23:47:24' | INFO  | Deleting Project 'fb8f2fd7-154d-46b0-947a-402ceea34b22'

status                                                                                                    spec
------                                                                                                    ----
@{state=COMPLETE; access_control_policy_list_status=System.Object[]; project_status=; execution_context=} @{access_con…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ProjectUuid
  )

  write-log -message "Deleting Project '$($ProjectUuid)'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_projects/$($ProjectUuid)"
    Method      = "DELETE"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Create PC Project 
##################################################################

Function REST-Create-Pc-Project {
<#
.SYNOPSIS
Deletes in Prism Central, Requires Project object as input

.DESCRIPTION
Creates the skeleton project and adds the PC Account

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER PcAccount  
PcAccount As weird as this is, the PcAccount needs to be the Pc account, not for the cluster itself.

.PARAMETER ProjectName
ProjectName, name of the project

.EXAMPLE
REST-Create-Pc-Project `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ProjectName $ProjectName `
  -PCAccount $Account

status                               spec                                                                                                                       api_version metadata
------                               ----                                                                                                                       ----------- --------
@{state=PENDING; execution_context=} @{access_control_policy_list=System.Object[]; project_detail=; user_list=System.Object[]; user_group_list=System.Object[]} 3.1         @{owner_reference=; use_categories_mapping=False; kind=project; spec_version=0;…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ProjectName,
    [parameter(mandatory)] [Object] $PcAccount

  )

  $PsHashPayload= @{
    spec = @{
      project_detail = @{
        name = $ProjectName
        resources = @{
          user_reference_list = @()
          external_user_group_reference_list = @()
          account_reference_list = @(@{
            uuid = $PCAccount.metadata.uuid
            kind = "account"
            name = "nutanix_pc"
          })
        }
      }
      user_list = @()
      user_group_list = @()
      access_control_policy_list = @()
    }
    api_version ="3.0"
    metadata = @{
      kind = "project"
    }
  } 

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIP):9440/api/nutanix/v3/projects_internal"
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Delete PC Environment 
##################################################################

Function REST-Delete-Calm-Environment {
<#
.SYNOPSIS
Deletes environment by its uuid, not all environments can be deleted.

.DESCRIPTION
Suitable for 429 responses

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER EnvironmentUuid
EnvironmentUuid Use 

.EXAMPLE
 REST-Delete-Pc-Project -PcClusterIP xxx -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -ProjectUuid $project.metadata.uuid
'31-Jul-21 23:47:24' | INFO  | Deleting Project 'fb8f2fd7-154d-46b0-947a-402ceea34b22'

status                                                                                                    spec
------                                                                                                    ----
@{state=COMPLETE; access_control_policy_list_status=System.Object[]; project_status=; execution_context=} @{access_con…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $EnvironmentUuid
  )

  write-log -message "Deleting Environment '$($EnvironmentUuid)'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/environments/$($EnvironmentUuid)"
    Method      = "DELETE"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName) `
    -Retry 1 `
    -LastError $False
} 


##################################################################
# Get Calm Runlog output
##################################################################

Function REST-Get-Calm-Runlog-Output {
 <#
.SYNOPSIS
Pulls Calm Runlog details

.DESCRIPTION
Retrieves the details of the Calm App Runlog output

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER AppUuid
AppUuid UUID of the calm app.

.PARAMETER RunLogUuid 
RunLogUuid, needs to be retrieved through Calm App Detail.

.EXAMPLE
REST-Get-Calm-Runlog-Output `
  -PCClusterIP $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -AppUuid $app.metadata.uuid `
  -RunlogUuid $target.metadata.uuid
'24-Aug-21 16:30:02' | INFO  | Getting Runlog data: 'aaace303-90ce-4193-95fd-2ebeccf02392'

status                                                            spec metadata
------                                                            ---- --------
@{runlog_state=SUCCESS; output_list=System.Object[]; exit_code=0}      @{uuid=aaace303-90ce-4193-95fd-2ebeccf02392}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $AppUuid,
    [parameter(mandatory)] [string] $RunlogUuid

  )

  write-log -message "Getting Runlog data: '$RunlogUuid'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/$($AppUuid)/app_runlogs/$($RunlogUuid)/output"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Update Calm Blueprint object.
##################################################################

Function REST-Update-Calm-Blueprint-Object {
 <#
.SYNOPSIS
Sends a generic object update to a calm blueprint

.DESCRIPTION
Requires the detailed object, modified to your needs as input.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER BlueprintDetail
BlueprintDetail Detailed Blueprint object, modified to your needs as input.

.EXAMPLE
REST-Update-Calm-Blueprint-Object `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -BlueprintDetail $BpObject
'19-Oct-21 10:00:44' | INFO  | Updating Blueprint 'a7f4dfe9-e158-4355-905f-891c6808e48a'
'19-Oct-21 10:00:44' | INFO  | Stripping 'Status'

status                                                                                                                                                                                                                            spec
------                                                                                                                                                                                                                            ----
@{description=This is the site control panel used to retrieve site information. …                                                                                                                                                 @{name=143da1e6-085a-4e3a…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $BlueprintDetail
  )

  write-log -message "Updating Blueprint '$($BlueprintDetail.metadata.uuid)'"
  write-log -message "Stripping 'Status'"

  $BlueprintDetail.psobject.members.remove("Status")

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIP):9440/api/nutanix/v3/blueprints/$($BlueprintDetail.metadata.uuid)"
    Method      = "PUT"
    Headers     = $AuthHeader
    Body        = $BlueprintDetail
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Launch Calm MarketPlace Blueprint.
##################################################################

Function REST-PrepLaunch-Calm-Marketplace-Blueprint {
<#
.SYNOPSIS
Sends a generic object update to a calm blueprint

.DESCRIPTION
Requires the detailed object, modified to your needs as input.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER BlueprintDetail
BlueprintDetail Detailed Blueprint object, modified to your needs as input.

.EXAMPLE
REST-PrepLaunch-Calm-Marketplace-Blueprint `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ProjectDetail $Projectdetail `
  -MktDetail $Mktdetail `
  -AppProfileIndex 0

status
------
@{description=Group of predefined workloads. The workload will be build, and registered to the corresponding workload API endpoints.…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [object] $MktDetail,
    [parameter(mandatory)] [object] $ProjectDetail,
                           [int]    $AppProfileIndex = 0
  )

  if($ProjectDetail.spec.project_detail.resources.default_environment_reference.uuid.length -le 5){

    write-log -message "This project does not have a working environment" -sev "ERROR" -errorcode "UNDEFINED"

  }

  $PsHashPayload = @{
    spec = @{
      description = $MktDetail.spec.description
      resources = $MktDetail.Spec.resources.app_blueprint_template.spec.resources
      source_marketplace_name = $MktDetail.spec.name
      source_marketplace_version = $MktDetail.spec.resources.version
      app_blueprint_name = "$($MktDetail.spec.name)$(get-random 999)"
      environment_profile_pairs = @(@{
        environment = @{
          uuid = $ProjectDetail.spec.project_detail.resources.default_environment_reference.uuid
        }
        app_profile = @{
          name = $MktDetail.spec.resources.app_blueprint_template.spec.resources.app_profile_list[$AppProfileIndex].name
        }
      })
    }
    api_version = "3.0"
    metadata = @{
      kind = "blueprint"
      project_reference = @{
        kind = "project"
        uuid = $ProjectDetail.metadata.uuid
      }
    }
  }

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/marketplace_launch"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Launch Calm MarketPlace Blueprint.
##################################################################

Function REST-Update-Calm-Marketplace-BlueprintObject {
<#
.SYNOPSIS
Sends a generic object update to a calm marketplace blueprint

.DESCRIPTION
Requires the detailed object, modified to your needs as input.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER MktDetail
MktDetail Detailed Marketplace Blueprint, modified to your needs as input.

.EXAMPLE
REST-Update-Calm-Marketplace-BlueprintObject `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -MktDetail $MktDetail
'19-Oct-21 10:31:29' | INFO  | Updating MarketPlace '025af5e3-61af-4178-a9ea-6e95cd89883b'
'19-Oct-21 10:31:29' | INFO  | Stripping 'Status'
'19-Oct-21 10:31:29' | INFO  | Executing PUT on 025af5e3-61af-4178-a9ea-6e95cd89883b

status
------
@{description=Group of predefined workloads. The workload will be build, and registered to the corresponding workload API endpoints.…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [object] $MktDetail
  )

  write-log -message "Updating MarketPlace '$($MktDetail.metadata.uuid)'"
  write-log -message "Stripping 'Status'"

  $MktDetail.psobject.members.remove("Status")

  write-log -message "Executing PUT on $($MktDetail.metadata.uuid)"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items/$($MktDetail.metadata.uuid)"
    Method      = "PUT"
    Headers     = $AuthHeader
    Body        = $MktDetail
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Calm Icon List
##################################################################

Function REST-Get-Calm-Marketplace-Icons {
<#
.SYNOPSIS
Sends a generic object update to a calm marketplace blueprint

.DESCRIPTION
Requires the detailed object, modified to your needs as input.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.EXAMPLE
rEST-Get-Calm-Marketplace-Icons `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'19-Oct-21 10:37:19' | INFO  | Query Icons

api_version metadata                          entities
----------- --------                          --------
3.0         @{total_matches=7; kind=app_icon} {@{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}…}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Query Icons"

  $PsHashPayload = @{
    length = 20
    offset= 0 
  }

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/app_icons/list"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Delete Calm Blueprint
##################################################################

Function REST-Delete-Calm-Blueprint {
<#
.SYNOPSIS
Deletes a Calm blueprint, hidden or not.

.DESCRIPTION
Deletes the blueprint based on its UUID. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER BluePrintUuid
BluePrintUuid uuid of the blueprint to be deleted

.EXAMPLE
REST-Delete-Calm-Blueprint `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -BluePrintUUID $BluePrintUUID
'19-Oct-21 11:10:39' | INFO  | Deleting Blueprint 'cdd809c8-c272-49e3-a941-10dd1629bcd5'

description
-----------
App Blueprint with uuid cdd809c8-c272-49e3-a941-10dd1629bcd5 deleted.
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $BluePrintUuid
  )

  write-log -message "Deleting Blueprint '$BluePrintUuid'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$BluePrintUUID"
    Method      = "DELETE"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Calm Blueprint Detail
##################################################################

Function REST-Get-Calm-Blueprint-Detail {
<#
.SYNOPSIS
Pulls a Calm blueprint detailed object, hidden or not.

.DESCRIPTION
Pulls the blueprint based on its UUID. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER BluePrintUuid
BluePrintUuid uuid of the blueprint to be deleted

.EXAMPLE
REST-Get-Calm-Blueprint-Detail `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -BluePrintUuid $BluePrintUuid | fl
'19-Oct-21 11:19:12' | INFO  | Pulling Blueprint 'ea7dc740-d54c-4625-8651-44c376cc9a1e'

status      : 
spec        : 
api_version : 
metadata    : @{last_update_time=1633903467939501; owner_reference=; kind=blueprint; uuid=ea7dc740-d54c-4625-8651-44c376cc9a1e; project_reference=; spec_version=2; creation_time=1633903393531702; name=1CN_FW_MarketPlace_New_Site}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $BluePrintUuid
  )

  write-log -message "Pulling Blueprint '$BluePrintUuid'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$BluePrintUuid"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Calm Blueprint Detail
##################################################################

Function REST-Add-Calm-MarketPlace-BluePrint {
<#
.SYNOPSIS
Pulls a Calm blueprint detailed object, hidden or not.

.DESCRIPTION
Pulls the blueprint based on its UUID. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER BluePrintUuid
BluePrintUuid uuid of the blueprint to be deleted

.PARAMETER Release
Release version of the blueprint

.PARAMETER AppGroupUuid  
AppGroupUuid Just Random Guid is fine

.PARAMETER IconUuid
ICON Uuid to use for this publication

.PARAMETER Name
Name for the marketplace item

.EXAMPLE
REST-Add-Calm-MarketPlace-BluePrint `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -BpObject $Payload `
  -Release $Release `
  -Project $Project `
  -AppGroupUuid (new-guid).guid `
  -Name $BpName `
  -IconUuid $IconUuid
'19-Oct-21 12:39:58' | INFO  | Stripping BP
'19-Oct-21 12:39:58' | INFO  | Adding '08311ae4-8b6d-43fb-9f68-547c454e895f' Project into the BluePrint
'19-Oct-21 12:39:58' | INFO  | Adding 'ee720687-b5d2-4b1e-947a-1b968cec6b6d' Icon into BluePrint
'19-Oct-21 12:39:58' | INFO  | Loading BP into the marketplace, pending approval.

status
------
@{description=This tool is for IT Infra Administrators only. It should not be used without CAB approval!…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $BpObject,
    [parameter(mandatory)] [object] $Project,
    [parameter(mandatory)] [string] $Release,
    [parameter(mandatory)] [string] $AppGroupUuid,
    [parameter(mandatory)] [string] $IconUuid,
    [parameter(mandatory)] [string] $Name
  )

  write-log -message "Stripping BP"

  $BPObject.psobject.properties.Remove('api_version')
  $BPObject.psobject.properties.Remove('metadata')

  write-log -message "Adding '$($Project.metadata.uuid)' Project into the BluePrint"
  write-log -message "Adding '$IconUuid' Icon into BluePrint"

  $PsHashPayload = @{
    api_version = "3.0"
    metadata = @{
      kind = "marketplace_item"
    }
    spec = @{
      name = $name
      description = $bpobject.spec.Description
      resources = @{
        app_attribute_list = @("FEATURED")
        icon_reference_list = @(@{
          icon_type = "ICON"
          icon_reference = @{
            kind = "file_item"
            uuid = $IconUuid
          }
        })
        author = "BPAutonomics"
        app_state = "PENDING"
        app_blueprint_template = $BpObject
        version = $Release
        app_group_uuid = $AppGroupUuid
        project_reference_list = @(@{
          name = $Project.metadata.project_reference.name
          kind = "project"
          uuid = $Project.metadata.uuid
        })
      }
    }
  }  

  write-log -message "Loading BP into the marketplace, pending approval."

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Publish Marketplace item
##################################################################

Function REST-Publish-Calm-MarketPlace-BluePrint {
<#
.SYNOPSIS
Approves a blueprint inside the market place for one or more projects.

.DESCRIPTION
Merges the project object input, array of projects.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER BpObject 
BpObject Marketplace Blueprint object that is to be moved to published state.

.PARAMETER Projects
Projects, array of projects (not entities) that need to be published towards.

.EXAMPLE
REST-Publish-Calm-MarketPlace-BluePrint `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Projects $Projects `
  -BpObject $MktDetail
'19-Oct-21 13:03:44' | INFO  | Stripping Object properties from Detailed object
'19-Oct-21 13:03:44' | INFO  | Adding 'Psdads00' Project into the BluePrint
'19-Oct-21 13:03:44' | INFO  | Setting State to Published.
'19-Oct-21 13:03:44' | INFO  | Publishing Marketplace Item '4f8a9109-d5ec-4b99-a35a-8a1e3265642a'

status      : 
spec        : 
api_version : 3.0
metadata    :
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [object] $BpObject,
    [parameter(mandatory)] [object] $Projects
  )

  write-log -message "Stripping Object properties from Detailed object"

  if ($BPobject.psobject.members.name -contains "status"){
    $BPobject.psobject.members.Remove("status")

    write-log -message "Removing Status"

  } 

  $SortedProjects = $Projects | sort-object -property @{e={$_.metadata.project_reference.name}} 

  foreach ($project in $SortedProjects){

    write-log -message "Adding '$($project.metadata.uuid)' Project into the BluePrint" -d 2
    write-log -message "Adding '$($project.metadata.project_reference.name)' Project into the BluePrint"

    $Payload = @{
    
      name = $project.metadata.project_reference.name
      kind = "project"
      uuid = $project.metadata.uuid
    }

    [array]$BpObject.spec.resources.project_reference_list += $Payload
 
  }

  [array]$BpObject.spec.resources.project_reference_list  = $BpObject.spec.resources.project_reference_list | sort-object -property @{e={$_.name}}
  
  write-log -message "Setting State to Published."

  $BpObject.spec.resources.app_state = "PUBLISHED"

  write-log -message "Publishing Marketplace Item '$($BpObject.metadata.uuid)'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items/$($BpObject.metadata.uuid)"
    Method      = "PUT"
    Headers     = $AuthHeader
    Body        = $BpObject
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add Windows Endpoint 
##################################################################

Function REST-Add-Calm-EndPoint {
<#
.SYNOPSIS
Creates a Calm Endpoint, Currently Windows only 

.DESCRIPTION
Generates credential uuids and endpoint uuids and creates an endpoint using those object uuids.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER Project
Project object, used for project.metadata.uuid and project.status.name

.PARAMETER Ip 
Ip of the endpoint, only one supported in this function.

.PARAMETER Username
Username of the credential connecting to the endpoint.

.PARAMETER Password
Password of the credential connecting to the endpoint.

.PARAMETER CredName
CredName Name of the credential that's created inside this endpoint.

.PARAMETER EndpointName
Endpoint name, self explanitory, the name of the endpoint.

.EXAMPLE
REST-Add-Calm-EndPoint `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Ip $MainVars.Endpoints.FrameworkGateway `
  -Username "Temp" `
  -Password $MainVars.Creds.Calm_Vault.Central_GW_PSR.secret `
  -CredName "Calm_WinMgt_$random" `
  -EndPointName "FwPoshGateway-$($MainVars.NamingConvention.VpcName)_$random" `
  -Project $Project
'24-Oct-21 19:53:19' | INFO  | Generating new UUIDs
'24-Oct-21 19:53:19' | INFO  | Creating EndPoint: 'FwPoshGateway-Pasdad761'

status                                                                                                            spec                                                    api_version metadata
------                                                                                                            ----                                                    ----------- --------
@{description=; message_list=System.Object[]; state=ACTIVE; resources=; name=FwPoshGateway-PTSEsad1} @{name=FwPoshGateway-PTSEEasddsasad27761; resources=} 3.0         @{last_update_time=1635097999639533; use_categories_mapping=False; ki…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [object] $Project,
    [parameter(mandatory)] [string] $Ip,
    [parameter(mandatory)] [string] $Username,
    [parameter(mandatory)] [string] $Password,
    [parameter(mandatory)] [string] $CredName,
    [parameter(mandatory)] [string] $EndpointName
  )

  write-log -message "Generating new UUIDs"

  $CredUuid = (new-guid).guid
  $EndPointUuid = (new-guid).guid

  $PsHashPayload = @{
    api_version = "3.0"
    metadata = @{
      kind = "endpoint"
      project_reference = @{
        name = $Project.status.name
        kind = "project"
        uuid = $Project.metadata.uuid
      }
      uuid = $EndPointUuid
    }
    spec = @{
      name = $EndPointName
      resources = @{
        type = "Windows"
        attrs = @{
          credential_definition_list = @(@{
            description = ""
            username = $Username
            type = "PASSWORD"
            name = $CredName
            secret = @{
              attrs = @{
                is_secret_modified = $true
              }
              value = $Password
            }
            uuid = $CredUuid
          })
          login_credential_reference = @{
            name = $CredName
            kind = "app_credential"
            uuid = $CredUuid
          }
          values = @("$($IP)")
          value_type = "IP"
          port = "5985"
          connection_protocol = "http"
        } 
      }
    }
  }  

  write-log -message "Creating EndPoint: '$EndPointName'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/endpoints"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Endpoint Detail 
##################################################################

Function REST-Get-Calm-EndPoint-Detail {
<#
.SYNOPSIS
Creates a Calm Endpoint, Currently Windows only 

.DESCRIPTION
Generates credential uuids and endpoint uuids and creates an endpoint using those object uuids.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER EndpointUuid
Uuid ID of the object to retrieve detailed view from.

.EXAMPLE
REST-Get-Calm-EndPoint-Detail `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -EndpointUuid $MyEndpoint.MetaData.uuid
'24-Oct-21 19:57:10' | INFO  | Pulling EndPoint: 'e4de6e3d-b710-49a9-b4f7-c427c82ed04f'

status                                                                                                     spec                                             api_version metadata
------                                                                                                     ----                                             ----------- --------
@{description=; message_list=System.Object[]; state=ACTIVE; resources=; name=FwPoshGateway-PTSEELM-NXC000} @{name=FwPoshGateway-PTSEELM-NXC000; resources=} 3.0         @{last_update_time=1634993893770670; owner_reference=; kind=endpoint; uuid=e4de6e3d…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $EndpointUuid
  )

  write-log -message "Pulling EndPoint: '$EndpointUuid'"

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIP):9440/api/nutanix/v3/endpoints/$($EndpointUuid)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Update Endpoint Object 
##################################################################

Function REST-Update-Calm-EndPoint-Object {
<#
.SYNOPSIS
Updates a Calm Endpoint

.DESCRIPTION
Updates a calm endpoint object

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER EndPointObj
Endpoint object, use REST-Get-Calm-EndPoint-Detail as input.

.EXAMPLE
REST-Update-Calm-EndPoint-Object `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -EndpointObj $EndpointObj
'24-Oct-21 20:07:12' | INFO  | Updating EndPoint: 'e4de6e3d-b710-49a9-b4f7-c427c82ed04f'

status                                                                                                     spec                                             api_version metadata
------                                                                                                     ----                                             ----------- --------
@{description=; message_list=System.Object[]; state=ACTIVE; resources=; name=FwPoshGateway-PTSEELM-NXC000} @{name=FwPoshGateway-xxx; resources=} 3.0         @{last_update_time=1635098832639078; use_categories_mapping=False; kind=endpoint; n…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $EndPointObj
  )

  write-log -message "Updating EndPoint: '$($EndPointObj.metadata.uuid)'"

  if ($EndPointObj.psobject.members.name -contains "status"){

    $EndPointObj.psobject.members.Remove("status")

    write-log -message "Removing Status"

  } 

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIP):9440/api/nutanix/v3/endpoints/$($EndPointObj.metadata.uuid)"
    Method      = "PUT"
    Headers     = $AuthHeader
    Body        = $EndPointObj
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Delete Endpoint Object 
##################################################################

Function REST-Delete-Calm-EndPoint {
<#
.SYNOPSIS
Deletes a calm endpoint.

.DESCRIPTION
Removes the object completely, used for project recreation mostly

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER EndPointUuid
EndPointUuid UUid of the object to be deleted.

.EXAMPLE
REST-Delete-Calm-EndPoint `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -EndPointUuid $EndPointUuid
'24-Oct-21 20:12:42' | INFO  | Deleting EndPoint: '5a4f7f9e-b80d-441e-8b65-5905bcd82e7c'

description
-----------
Endpoint with name FwPoshGateway-PTSEELM-NXC000_727761 deleted.
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $EndPointUuid
  )

  write-log -message "Deleting EndPoint: '$($EndPointUuid)'"

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIP):9440/api/nutanix/v3/endpoints/$($EndPointUuid)"
    Method      = "DELETE"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Get Endpoints
##################################################################

Function REST-Get-Calm-EndPoints {
<#
.SYNOPSIS
Pulls all calm endpoints, list, Uses Pagination 

.DESCRIPTION
Pulls a list of calm endpoints, Uses Pagination 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.EXAMPLE
REST-Get-Calm-EndPoints `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'24-Oct-21 20:17:10' | INFO  | Pulling all available endpoints

api_version metadata                          entities
----------- --------                          --------
3.0         @{total_matches=2; kind=endpoint} {@{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload =@{
    kind = "endpoint"
    length = 50
    offset = 0
    filter = "_state!=DELETED"
  }

  write-log -message "Pulling all available endpoints"

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIP):9440/api/nutanix/v3/endpoints/list"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Export Blueprint with Secrets
##################################################################

Function REST-Export-Calm-BluePrint-WithSecrets {
<#
.SYNOPSIS
Exports a blueprint with the Secrets kept intact

.DESCRIPTION
This is required / used for blueprints that are launched from the marketplace.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER BluePrintUuid
BluePrintUuid ID of the object being exported.

.EXAMPLE
REST-Export-Calm-BluePrint-WithSecrets `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -BluePrintUuid $uuid | fl
'24-Oct-21 20:26:54' | INFO  | Downloading 'ea7dc740-d54c-4625-8651-44c376cc9a1e' with secrets

status      : 
spec        : 
api_version : 3.0
metadata    : @{last_update_time=1633903467939501; kind=blueprint; spec_version=2; creation_time=1633903393531702; name=1CN_FW_MarketPlace_New_Site}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $BluePrintUuid
  )

  write-log -message "Downloading '$BluePrintUuid' with secrets"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($BluePrintUuid)/export_json?keep_secrets=true"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Import Generic Blueprint
##################################################################

Function REST-Import-Calm-BluePrint {
<#
.SYNOPSIS
Imports any blueprint into a project inside calm

.DESCRIPTION
Any normally exported blueprint can be fed in, without modifications

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER Project
Project Object

.PARAMETER BpFilePath
BpFilePath Full path to blueprint file

.PARAMETER RandomizeName
RandomizeName Randomizes the name of the blueprint on import.

.PARAMETER BpName
BpName if randomize is true, this parameter is not required

.EXAMPLE
REST-Import-Calm-BluePrint `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -BpFilePath "$($MainVars.MetaData.BluePrintDir)\1CN_FW_ControlPanel_S.json" `
  -Project $Project `
  -RandomizeName $true |fl
'24-Oct-21 21:48:37' | INFO  | Loading Json
'24-Oct-21 21:48:37' | INFO  | Stripping Object properties from Detailed object
'24-Oct-21 21:48:37' | INFO  | Removing contains_secrets
'24-Oct-21 21:48:37' | INFO  | Removing Status
'24-Oct-21 21:48:37' | INFO  | Removing Product Version
'24-Oct-21 21:48:37' | INFO  | Creating random BPname '0c1b1b54-f689-4e46-bbc5-a96f76e1794c'
'24-Oct-21 21:48:37' | INFO  | Adding Project 08311ae4-8b6d-43fb-9f68-547c454e895f ID into BluePrint

status      : @{description=This is the site control panel used to retrieve site information.
              Do not delete.; source_mpi=; state=DRAFT; is_cloned=False; message_list=System.Object[]; resources=; name=0c1b1b54-f689-4e46-bbc5-a96f76e1794c}
spec        : @{name=0c1b1b54-f689-4e46-bbc5-a96f76e1794c; resources=; description=This is the site control panel used to retrieve site information.
              Do not delete.}
api_version : 3.0
metadata    : @{last_update_time=1635104919629873; use_categories_mapping=False; kind=blueprint; name=0c1b1b54-f689-4e46-bbc5-a96f76e1794c; project_reference=; spec_version=0; creation_time=1635104919629873; categories_mapping=; owner_reference=;
              categories=; uuid=c3f5eb89-ca77-4482-89dc-02dc248740ce}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [object] $Project,
    [parameter(mandatory)] [string] $BpFilePath,
                           [bool]   $RandomizeName = $false,
                           [string] $BpName
  )

  write-log -message "Loading Json"

  $BpObject = (get-content $BpFilePath) | convertfrom-json

  write-log -message "Stripping Object properties from Detailed object"

  if ($BpObject.psobject.members.name -contains "contains_secrets"){
    $BpObject.psobject.members.Remove("contains_secrets")

    write-log -message "Removing contains_secrets"

  } 
  if ($BpObject.psobject.members.name -contains "status"){
    $BpObject.psobject.members.Remove("status")

    write-log -message "Removing Status"

  } 
  if ($BpObject.psobject.members.name -contains "product_version"){
    $BpObject.psobject.members.Remove("product_version")

    write-log -message "Removing Product Version"

  }
  if ($RandomizeName){

    $BpName =  (New-Guid).guid

    write-log -message "Creating random BluePrint Name '$BpName'"

  } 

  $BpObject.metadata.name = $BpName
  $BpObject.spec.name     = $BpName

  write-log -message "Adding Project $($project.metadata.uuid) ID into BluePrint"

  if (!$BpObject.metadata.project_reference){
    $child = @{
      uuid = "0"
      kind = "project"
    }
    $BpObject.metadata | add-member -notepropertyname project_reference $child -force
  }

  $BpObject.metadata.project_reference.uuid = $project.metadata.uuid

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/import_json"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $BpObject
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Detailed Calm App Runlog
##################################################################

Function REST-Get-Calm-App-DetailRunlog {
<#
.SYNOPSIS
Pulls the detailed run log for an item in the audit tab of a calm app.

.DESCRIPTION
This is used to read logging output and status.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER MainLogUuid
MainLogUuid ID of the log being pulled.

.PARAMETER AppUuid
AppUuid ID of the running App we query

.EXAMPLE
REST-Get-Calm-App-DetailRunlog `
  -PCClusterIP $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -AppUuid $AppUuid `
  -MainLogUuid $MainLogUuid
'25-Oct-21 10:15:39' | INFO  | Query Calm App '405b2434-87cb-4de8-91be-abc048e94bdf' pulling log '7db19f00-c935-4d9a-8a5b-7de0b6d20652'

api_version metadata                            entities
----------- --------                            --------
3.0         @{total_matches=5; kind=app_runlog} {@{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}…}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $MainLogUuid,
    [parameter(mandatory)] [string] $AppUuid

  )

  $PsHashPayload = @{
    filter = "root_reference==$($MainLogUuid)"
  }

  write-log -message "Query Calm App '$AppUuid' pulling log '$MainLogUuid'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/$($AppUuid)/app_runlogs/list"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Detailed Calm App Mainlog
##################################################################

Function REST-Get-Calm-App-Mainlog {
<#
.SYNOPSIS
Pulls the Audit Tab Top level logs. use REST-Query-Calm-App-MainRunlog for individual logs once the main log has been retrieved.

.DESCRIPTION
This is required / used for blueprints that are launched from the marketplace.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER AppUuid
AppUuid ID of the running App we query

.EXAMPLE
REST-Get-Calm-App-Mainlog -PcClusterIP $MainVars.AutoDC.PcClusterIP -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -AppUuid 7048161a-aa20-49cc-a8b6-899ef3dc922e
'16-Nov-21 22:24:15' | INFO  | Query Calm App '7048161a-aa20-49cc-a8b6-899ef3dc922e' pulling Main Log

api_version metadata                             entities
----------- --------                             --------
3.0         @{total_matches=28; kind=app_runlog} {@{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $AppUuid

  )

  $PsHashPayload = @{
    filter = "application_reference==$($AppUuid);(type==action_runlog,type==audit_runlog,type==ngt_runlog,type==clone_action_runlog,type==platform_sync_runlog)"
  }

  write-log -message "Query Calm App '$AppUuid' pulling Main Log"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/$($AppUuid)/app_runlogs/list"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Calm Apps
##################################################################

Function REST-Get-Calm-Apps {
<#
.SYNOPSIS
Pulls all calm Apps, list, 50 max using pagination function.

.DESCRIPTION
Pulls a list of calm apps, no limit!

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.EXAMPLE
REST-Get-Calm-EndPoints `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'24-Oct-21 20:17:10' | INFO  | Pulling all available endpoints

api_version metadata                          entities
----------- --------                          --------
3.0         @{total_matches=2; kind=endpoint} {@{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; metadata=}}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload =@{
    kind = "app"
    length = 50 # Default Pagination Setting. No need to set this higher.
    offset = 0 # Controlled by Pagination Function.
  }

  write-log -message "Pulling all calm Apps"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/list"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Delete Calm App (Soft)
##################################################################

Function REST-Delete-Calm-App {
<#
.SYNOPSIS
Deletes a calm app Soft or Normal

.DESCRIPTION
Calm apps can be deleted in 2 different ways, Soft or Normal.
Soft deletes are useful if the resources themselves don't have to be destroyed.
Soft deletes also prevent the uninstall code from being executed.
Normal deletes delete the App, the VM and executes the uninstall code.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER Type
Type soft or something else. 

.EXAMPLE
REST-Delete-Calm-App -PcClusterIP 10.230.88.27 -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -AppUuid e0abdb7d-5cc4-4870-b663-2296cff7a2d3
'30-Dec-21 13:14:02' | INFO  | Deleting Calm App 'e0abdb7d-5cc4-4870-b663-2296cff7a2d3' type : 'Normal'

status                                                                                                    api_version
------                                                                                                    -----------
@{runlog_uuid=d4b06ee0-1232-49d2-8627-a9908add9662; ergon_task_uuid=27f5cbac-6a16-41c8-b24c-ecc98f2caae2} 3.0
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $AppUuid,
                           [string] $Type = "Normal"
  )

  write-log -message "Deleting Calm App '$($AppUuid)' type : '$type'"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/apps/$($AppUuid)"
    Method      = "Delete"
    Headers     = $AuthHeader
  }

  if ($type -eq "soft"){
    $RequestPayload.uri = $RequestPayload.uri + "?type=soft"
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Get Calm BluePrints
##################################################################

Function REST-Get-Calm-BluePrints {
<#
.SYNOPSIS
Pulls all calm Apps, list, 50 max using pagination function.

.DESCRIPTION
Pulls a list of calm apps, no limit!

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.EXAMPLE
REST-Get-Calm-BluePrints `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'16-Nov-21 23:23:18' | INFO  | Pulling all calm Apps
'16-Nov-21 23:23:18' | INFO  | Converting Object
'16-Nov-21 23:23:19' | INFO  | We found '2' items.

Name                           Value
----                           -----
api_version                    3.0
entities                       {@{status=; spec=; api_version=3.0; metadata=}, @{status=; spec=; api_version=3.0; meta…
metadata                       {total_matches, offset, length, kind}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload =@{
    kind = "blueprint"
    length = 50 # Default Pagination Setting. No need to set this higher.
    offset = 0 # Controlled by Pagination Function.
  }

  write-log -message "Pulling all calm Apps"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/list"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Get Calm BluePrints
##################################################################

Function REST-Launch-Calm-BluePrint {
<#
.SYNOPSIS
Launches a calm Blueprint

.DESCRIPTION
Requires the detailed blueprint as input object, and launches the blueprint with the given app name.
The Launch itself does additional validation after it returns the API result.
A successful launch command, does not mean a successful launch.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER BpObject
Use REST-Get-Calm-Blueprint-Detail to retrieve.

.PARAMETER AppName
The name of the application once launched.

.PARAMETER LoggingDir
The Directory that hold the working space for this execution. 
Problems with Blueprints are difficult to troubleshoot, this dumps the blueprint to disk.

.EXAMPLE
REST-Launch-Calm-BluePrint -PcClusterIP 10.230.88.27 -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -BpObject $BpDetail -AppName "TestCodeDocu" -LoggingDir $MainVars.Metadata.LoggingDir
'30-Dec-21 13:18:49' | INFO  | Working with BP UUID 95cc037a-8ce0-46ec-9b6f-10993e519090
'30-Dec-21 13:18:49' | INFO  | App Name: 'TestCodeDocu'
'30-Dec-21 13:18:49' | INFO  | Stripping Object properties from Detailed object
'30-Dec-21 13:18:49' | INFO  | Removing Status
'30-Dec-21 13:18:49' | INFO  | Executing Launch on BP '95cc037a-8ce0-46ec-9b6f-10993e519090'
'30-Dec-21 13:18:49' | INFO  | Pulling all calm Apps

status                                                              spec
------                                                              ----
@{is_cloned=False; request_id=fcb299ca-52ae-48c2-bf39-70e5df086733} @{application_name=TestCodeDocu; app_profile_refer…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [object] $BpObject,
    [parameter(mandatory)] [string] $AppName,
                           [string] $LoggingDir
  )

  write-log -message "Working with BP UUID $($BPobject.metadata.uuid)"
  write-log -message "App Name: '$AppName'"

  $BpObject.spec  | add-member noteproperty application_name $AppName -force
  $AppProfile = @{
    app_profile_reference = @{
      kind = "app_profile"
      uuid = $BpObject.spec.resources.app_profile_list.uuid
    }
  }

  $BpObject.spec  | add-member noteproperty app_profile_reference "temp" -force
  $BpObject.spec.app_profile_reference = $AppProfile.app_profile_reference

  write-log -message "Stripping Object properties from Detailed object"

  if ($BpObject.psobject.members.name -contains "contains_secrets"){
    $BpObject.psobject.members.Remove("contains_secrets")

    write-log -message "Removing contains_secrets"

  } 
  if ($BpObject.psobject.members.name -contains "status"){
    $BpObject.psobject.members.Remove("status")

    write-log -message "Removing Status"

  } 
  if ($BpObject.psobject.members.name -contains "product_version"){
    $BpObject.psobject.members.Remove("product_version")

    write-log -message "Removing Product Version"

  }
  $BpObject.spec.psobject.members.Remove("name")

  if ($Debug -ge 2 -and $LoggingDir){
    $BpObject | ConvertTo-Json -depth 100 | out-file "$($LoggingDir)\GenbplaunchFull.json"
  }

  write-log -message "Executing Launch on BP '$($BPobject.metadata.uuid)'"
  write-log -message "Pulling all calm Apps"

  $RequestPayload = @{
    Uri         =  "https://$($PCClusterIP):9440/api/nutanix/v3/blueprints/$($BPobject.metadata.uuid)/launch"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $BpObject
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Execute Calm Action Item
##################################################################

Function REST-Run-Calm-Action-Item {
<#
.SYNOPSIS
Runs an action item of an existing Calm Application

.DESCRIPTION
Can be any action item, command options are optional. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER App
The Detailed Application object, can be the list item, $App.metadata.project_reference.name is required.

.PARAMETER ActionItem
The action item to Launch, e.g. ($Appdetail.spec.resources.action_list | where {$_.name -eq "Desired State Config"})

.EXAMPLE
REST-Run-Calm-Action-Item `
  -PCClusterIP $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -App $appdetail `
  -ActionItem ($appdetail.spec.resources.action_list | where {$_.name -eq "Desired State Config"}) | fl
'30-Dec-21 14:07:16' | INFO  | Using Project UUID: 'c2cb2158-848b-46d2-b562-0040a723fcc3'
'30-Dec-21 14:07:16' | INFO  | Executing Action Item: '8de18f7d-9e06-4f6b-93d5-5eadfc4d23b8' inside Calm app: '9c06cb6f-eb99-4067-b18f-98b2d1a5ad38'

status      : @{runlog_uuid=54d1b653-fb61-4853-adc7-43873eb94d3d}
spec        : @{args=System.Object[]; target_uuid=9c06cb6f-eb99-4067-b18f-98b2d1a5ad38; target_kind=Application}
api_version : 3.0
metadata    : @{use_categories_mapping=False; kind=app; name=Control Panel RETSE124-NXC000; project_reference=; categories=;
              uuid=869e03d4-172a-4ac6-bf99-79c16415ab46}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [object] $AuthHeader,
    [parameter(mandatory)] [object] $App,
    [parameter(mandatory)] [object] $ActionItem,
                           [string] $CommandOptions
  )
  $Guid = (new-guid).guid

  write-log -message "Using Project UUID: '$($app.metadata.project_reference.uuid)'"

  $PsHashPayload = @{
    api_version = "3.0"
    metadata = @{
      project_reference = @{
        kind = "project"
        name = $App.metadata.project_reference.name
        uuid = $App.metadata.project_reference.uuid
      }
      name = $App.metadata.name
      kind = "app"
      uuid = $Guid
    }
    spec = @{
      target_uuid = $App.Metadata.uuid
      target_kind = "Application"
      args = @()
    }
  }

  if ($CommandOptions){

    $Arguments = $CommandOptions | convertfrom-json
    $PsHashPayload.spec.args += $Arguments

  }

  write-log -message "Executing Action Item: '$($ActionItem.UUID)' inside Calm app: '$($app.metadata.uuid)'"

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIP):9440/api/nutanix/v3/apps/$($app.metadata.uuid)/actions/$($ActionItem.UUID)/run"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pull Marketplace items using group call.
##################################################################

Function REST-Get-Calm-Global-MarketPlace-Items {
<#
.SYNOPSIS
Gets all Marketplace items using a Prism Group call.

.DESCRIPTION
Group calls have unstructured output, at least for the human eye.
Yet group calls are high performing highly reliable, universal. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.EXAMPLE
REST-Get-Calm-Global-MarketPlace-Items `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'30-Dec-21 14:28:23' | INFO  | Getting All Market Place Items.
'30-Dec-21 14:28:23' | INFO  | Using Prism Group Call

entity_type           : marketplace_item
filtered_entity_count : 6
filtered_group_count  : 1
group_results         : {@{entity_results=System.Object[]; group_by_column_value=; group_summaries=; total_entity_count=6}}
total_entity_count    : 66
total_group_count     : 1
#>
  Param (
    [parameter(mandatory)] [string] $PCClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload = @{
    filter_criteria = "marketplace_item_type_list==APP"
    group_member_offset = 0
    group_member_count = 5000
    entity_type = "marketplace_item"
    group_member_attributes = @(
      @{
        attribute =  "name"
      }
      @{
        attribute =  "author"
      }
      @{
        attribute =  "version"
      }
      @{
        attribute =  "categories"
      }
      @{
        attribute =  "owner_reference"
      }
      @{
        attribute =  "owner_username"
      }
      @{
        attribute =  "project_names"
      }
      @{
        attribute =  "project_uuids"
      }
      @{
        attribute =  "app_state"
      }
      @{
        attribute =  "spec_version"
      }
      @{
        attribute =  "app_attribute_list"
      }
      @{
        attribute =  "app_group_uuid"
      }
      @{
        attribute =  "icon_list"
      }
      @{
        attribute =  "change_log"
      }
      @{
        attribute =  "app_source"
      }
    )
  }

  write-log -message "Getting All Market Place Items."
  write-log -message "Using Prism Group Call"

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/groups"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Delete Marketplace item
##################################################################

Function REST-Delete-Calm-MarketPlace-Item {
<#
.SYNOPSIS
Deletes a marketplace item from the marketplace...

.DESCRIPTION
You cannot delete a marketplace application in the status Published. Change the status to Accepted first.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER MktUuid
The UUID of the marketplace item to delete, REST-Get-Calm-Global-MarketPlace-Items to retrieve.

.EXAMPLE
REST-Delete-Calm-MarketPlace-Item `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -MktUuid 2f48c370-0f2d-4ddf-8e28-fa8220cd7375
'30-Dec-21 14:49:14' | INFO  | Deleting Market Place Item.

description
-----------
Marketplace Blueprint with uuid 2f48c370-0f2d-4ddf-8e28-fa8220cd7375 deleted.
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $MktUuid
  )

  write-log -message "Deleting Market Place Item."

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items/$($MktUuid)"
    Method      = "DELETE"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Marketplace item Detail.
##################################################################

Function REST-Get-Calm-GlobalMarketPlaceItem-Detail {
<#
.SYNOPSIS
Pulls the details of a marketplace item. 

.DESCRIPTION
Pulls the details of a published marketplace item.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER MktUuid
The UUID of the marketplace item to pull, REST-Get-Calm-Global-MarketPlace-Items to retrieve.

.EXAMPLE
REST-Get-Calm-GlobalMarketPlaceItem-Detail `
         -PcClusterIP $MainVars.AutoDC.PcClusterIP `
         -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
         -MktUuid 2f48c370-0f2d-4ddf-8e28-fa8220cd7375 | fl
'30-Dec-21 14:45:43' | INFO  | Getting Market Place Item Detail.

status   : @{description=Custom Marketplace deployment.

           Allows to deploy any name / app using framework logic.

           IPam registration and other integrations.

           Yet with any custom parameter.<br>Customer Version: master.<br>Core Framework Version: master.<br>; name=IKEA Custom Workload Dev; resources=}
spec     : @{description=Custom Marketplace deployment.

           Allows to deploy any name / app using framework logic.

           IPam registration and other integrations.

           Yet with any custom parameter.<br>Customer Version: master.<br>Core Framework Version: master.<br>; name=IKEA Custom Workload Dev; resources=}
metadata : @{last_update_time=1640788910654720; kind=marketplace_item; uuid=2f48c370-0f2d-4ddf-8e28-fa8220cd7375; owner_reference=; spec_version=5;
           creation_time=1640388532196416; name=IKEA Custom Workload Dev}
#>
 Param (
    [parameter(mandatory)] [string] $PCClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $MktUuid
  )

  write-log -message "Getting Market Place Item Detail."

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_marketplace_items/$($MktUuid)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Add Project User with RoleMapping
##################################################################

Function REST-Add-Project-User-WithRole-Object {
<#
.SYNOPSIS
Adds a user to a project with ACP Role Mapping.

.DESCRIPTION
Access Control Policies are the worst, next to Projects. This component uses both :)
This component mail fail for unknown reasons but is retry able.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER Role
The Role Object use REST-Get-Pc-Roles to retrieve a single entity

.PARAMETER User
The User Object use REST-Get-Pc-Users to retrieve a single entity

.PARAMETER ProjectDetail
The Project Object use REST-Query-Pc-Projects-FilterName to retrieve a single entity

.PARAMETER Cluster
The Cluster Object use 1CN-Get-PC-Clusters-Group to retrieve a single entity

.EXAMPLE
REST-Add-Project-User-WithRole-Object `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Project $Projectdetail `
  -Role $RunAppRole `
  -User $RunAppUser `
  -Cluster $Cluster
'30-Dec-21 16:04:16' | INFO  | Setting Existing ACP to 'UPDATE'
'30-Dec-21 16:04:16' | INFO  | Updating Project 'c2cb2158-848b-46d2-b562-0040a723fcc3' Object
'30-Dec-21 16:04:16' | INFO  | Stripping 'Status'
'30-Dec-21 16:04:16' | INFO  | Modifying Project Mapping.

status                               spec
------                               ----
@{state=PENDING; execution_context=} @{access_control_policy_list=System.Object[]; project_detail=; user_list=System.O…
#>
  Param (
    [parameter(mandatory)] [string] $PCClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $Role,
    [parameter(mandatory)] [Object] $User,   
    [parameter(mandatory)] [Object] $ProjectDetail,
    [parameter(mandatory)] [Object] $Cluster
  )

  write-log -message "Setting Existing ACP to 'UPDATE'" -d 2
  write-log -message "Updating Project '$($ProjectDetail.metadata.uuid)' Object"
  write-log -message "Stripping 'Status'" -d 2 

  $ProjectDetail.psobject.members.remove("Status")
  $ProjectDetail.spec.access_control_policy_list | % {
    $_ | add-member noteproperty operation "UPDATE" -force
  }
  $ACPGuid = (new-guid).guid

  $AcpHashPayload = @{
    acp = @{
      name = "1-click-nutanix-$ACPGuid"
      resources = @{
        role_reference = @{
          name = $Role.spec.name
          uuid = $Role.metadata.uuid
          kind = "role"
        }
        user_group_reference_list = @()
        user_reference_list = @(
          @{
            name = $User.status.name
            kind = "user"
            uuid = $User.metadata.uuid
          }
        )
        filter_list = @{
          context_list = @(
            @{
              entity_filter_expression_list = @(
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "ALL"
                  }
                  right_hand_side = @{
                     collection = "ALL"                 
                  }
                }
              )
              scope_filter_expression_list = @(
                @{
                  operator = "IN" 
                  left_hand_side = "PROJECT"
                  right_hand_side = @{
                    uuid_list = @($ProjectDetail.metadata.uuid)
                  }
                }
              )
            }
            @{
              entity_filter_expression_list = @(
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "image"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "marketplace_item"
                  }
                  right_hand_side = @{
                    collection = "SELF_OWNED"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "directory_service"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "role"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "project"
                  }
                  right_hand_side = @{
                    uuid_list = @($ProjectDetail.metadata.uuid)
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "user"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "user_group"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "environment"
                  }
                  right_hand_side = @{
                    collection = "SELF_OWNED"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "app_icon"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "category"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "app_task"
                  }
                  right_hand_side = @{
                    collection = "SELF_OWNED"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "app_variable"
                  }
                  right_hand_side = @{
                    collection = "SELF_OWNED"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "identity_provider"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "cluster"
                  }
                  right_hand_side = @{
                    uuid_list = @($Cluster.metadata.uuid)
                  }
                }
              )
            }
            @{
              entity_filter_expression_list = @(
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "blueprint"
                  }
                  right_hand_side = @{
                     collection = "ALL"                 
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "environment"
                  }
                  right_hand_side = @{
                     collection = "ALL"                 
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "marketplace_item"
                  }
                  right_hand_side = @{
                     collection = "ALL"                 
                  }
                }
              )
              scope_filter_expression_list = @(
                @{
                  operator = "IN"
                  left_hand_side = "PROJECT"
                  right_hand_side = @{
                    uuid_list = @($ProjectDetail.metadata.uuid)
                  }
                }
              )
            }
          )
        }
      }
      description = "ACP for Role:$($Role.spec.name)"
    }
    metadata = @{
      kind = "access_control_policy"
    }
    operation = "ADD"
  }

  $ProjectDetail.spec.access_control_policy_list += $AcpHashPayload

  write-log -message "Modifying Project Mapping."
  
  $UserResource = @{
    kind = "user"
    name = $User.status.name
    uuid = $User.metadata.uuid
  }

  $ProjectDetail.spec.project_detail.resources.user_reference_list += $UserResource

  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_projects/$($ProjectDetail.metadata.uuid)"
    Method      = "PUT"
    Body        = $ProjectDetail
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}


##################################################################
# Add Project Group with RoleMapping
##################################################################

Function REST-Add-Project-Group-WithRole-Object {
<#
.SYNOPSIS
Adds a user to a project with ACP Role Mapping.

.DESCRIPTION
Access Control Policies are the worst, next to Projects. This component uses both :)
This component mail fail for unknown reasons but is retry able.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster / Calm VIP on the dedicated instance.

.PARAMETER Role
The Role Object use REST-Get-Pc-Roles to retrieve a single entity

.PARAMETER Group
The User Object use REST-Get-Pc-Users to retrieve a single entity

.PARAMETER ProjectDetail
The Project Object use REST-Query-Pc-Projects-FilterName to retrieve a single entity

.PARAMETER Cluster
The Cluster Object use 1CN-Get-PC-Clusters-Group to retrieve a single entity

.EXAMPLE
REST-Add-Project-Group-WithRole-Object `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Project $Projectdetail `
  -Role $RunAppRole `
  -User $RunAppUser `
  -Cluster $Cluster
'30-Dec-21 16:04:16' | INFO  | Setting Existing ACP to 'UPDATE'
'30-Dec-21 16:04:16' | INFO  | Updating Project 'c2cb2158-848b-46d2-b562-0040a723fcc3' Object
'30-Dec-21 16:04:16' | INFO  | Stripping 'Status'
'30-Dec-21 16:04:16' | INFO  | Modifying Project Mapping.

status                               spec
------                               ----
@{state=PENDING; execution_context=} @{access_control_policy_list=System.Object[]; project_detail=; user_list=System.O…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $Role,
    [parameter(mandatory)] [Object] $Group,
    [parameter(mandatory)] [Object] $ProjectDetail,
    [parameter(mandatory)] [object] $Cluster
  )

  write-log -message "Setting Existing ACP to 'UPDATE'" -d 2
  write-log -message "Updating Project '$($ProjectDetail.metadata.uuid)' Object"
  write-log -message "Stripping 'Status'" -d 2 

  $ProjectDetail.psobject.members.remove("Status")
  $ProjectDetail.spec.access_control_policy_list | % {
    $_ | add-member noteproperty operation "UPDATE" -force
  }
  $ACPGuid = (new-guid).guid

  $AcpHashPayload = @{
    acp = @{
      name = "1-click-nutanix-$ACPGuid"
      resources = @{
        role_reference = @{
          name = $Role.spec.name
          uuid = $Role.metadata.uuid
          kind = "role"
        }
        user_group_reference_list = @(
          @{
            name = $Group.status.resources.display_name
            kind = "user_group"
            uuid = $Group.metadata.uuid
          }
        )
        user_reference_list = @()
        filter_list = @{
          context_list = @(
            @{
              entity_filter_expression_list = @(
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "ALL"
                  }
                  right_hand_side = @{
                     collection = "ALL"                 
                  }
                }
              )
              scope_filter_expression_list = @(
                @{
                  operator = "IN" 
                  left_hand_side = "PROJECT"
                  right_hand_side = @{
                    uuid_list = @($ProjectDetail.metadata.uuid)
                  }
                }
              )
            }
            @{
              entity_filter_expression_list = @(
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "image"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "marketplace_item"
                  }
                  right_hand_side = @{
                    collection = "SELF_OWNED"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "directory_service"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "role"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "project"
                  }
                  right_hand_side = @{
                    uuid_list = @($ProjectDetail.metadata.uuid)
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "user"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "user_group"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "environment"
                  }
                  right_hand_side = @{
                    collection = "SELF_OWNED"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "app_icon"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "category"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "app_task"
                  }
                  right_hand_side = @{
                    collection = "SELF_OWNED"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "app_variable"
                  }
                  right_hand_side = @{
                    collection = "SELF_OWNED"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "identity_provider"
                  }
                  right_hand_side = @{
                    collection = "ALL"
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "cluster"
                  }
                  right_hand_side = @{
                    uuid_list = @($Cluster.metadata.uuid)
                  }
                }
              )
            }
            @{
              entity_filter_expression_list = @(
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "blueprint"
                  }
                  right_hand_side = @{
                     collection = "ALL"                 
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "environment"
                  }
                  right_hand_side = @{
                     collection = "ALL"                 
                  }
                }
                @{
                  operator = "IN"
                  left_hand_side = @{
                    entity_type = "marketplace_item"
                  }
                  right_hand_side = @{
                     collection = "ALL"                 
                  }
                }
              )
              scope_filter_expression_list = @(
                @{
                  operator = "IN"
                  left_hand_side = "PROJECT"
                  right_hand_side = @{
                    uuid_list = @($ProjectDetail.metadata.uuid)
                  }
                }
              )
            }
          )
        }
      }
      description = "ACP for Role:$($Role.spec.name)"
    }
    metadata = @{
      kind = "access_control_policy"
    }
    operation = "ADD"
  }

  $ProjectDetail.spec.access_control_policy_list += $AcpHashPayload

  write-log -message "Modifying Project Mapping."
  
  $RequestPayload = @{
    Uri         = "https://$($PCClusterIP):9440/api/nutanix/v3/calm_projects/$($ProjectDetail.metadata.uuid)"
    Method      = "PUT"
    Body        = $ProjectDetail
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}
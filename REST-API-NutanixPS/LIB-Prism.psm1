##################################################################
# Get-Pe-Clusters 
##################################################################

Function REST-Get-Pe-Clusters-V3 {
<#
.SYNOPSIS
Retrieves all Clusters listed in Pe. Just includes itself

.DESCRIPTION
Generic API V3 Cluster query call, retrieves the clusters that are found on this Pe. Uses Pagination function to avoid any qyery limit cap.
This API call is known to send delayed responses, if you rename a cluster, it can take several minutes, based on Nutanix Engineering the force refresh parameter is added in the header.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp 
The name or IP for the Prism Element Cluster.

.EXAMPLE
REST-Get-Pe-Clusters-V3 `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'14-Jul-21 21:02:13' | INFO  | Building Cluster Query JSON

api_version metadata                         entities
----------- --------                         --------
3.1         @{total_matches=6; kind=cluster} {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; s…  
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [object] $AuthHeader
  )

  Write-Log -message "Building Cluster Query JSON"

  $PsHashPayload = @{
    kind="cluster"
    offset=0
    length=99999
  }

  $Headers = @{
    "Authorization" = $AuthHeader.Authorization
    "Force-Refresh" = $true
  }

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/api/nutanix/v3/clusters/list"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $Headers
  }

  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Get-PC-Clusters Group
##################################################################

Function REST-Get-PC-Clusters-V3-Group {
<#
.SYNOPSIS
Retrieves all Clusters listed in PC. This includes itself

.DESCRIPTION
Generic API V3 Cluster query call, retrieves the clusters that are found on this PC. Uses Pagination function to avoid any qyery limit cap.
This API call is known to send delayed responses, if you rename a cluster, it can take several minutes, based on Nutanix Engineering the force refresh parameter is added in the header.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.EXAMPLE
REST-Get-PC-Clusters-V3 `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'14-Jul-21 21:02:13' | INFO  | Building Cluster Query JSON

api_version metadata                         entities
----------- --------                         --------
3.1         @{total_matches=6; kind=cluster} {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; s…  
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [object] $AuthHeader
  )

  Write-Log -message "Building Cluster Query JSON - Group Method"


  $PsHashPayload = @{
    entity_type = "cluster"
    filter_criteria = "include_pc==true"
    group_member_attributes = $(@{
      attribute = "name"
    }
    @{
      attribute = "version"

    }
    @{
      attribute = "is_available"

    }
    @{
      attribute = "service_list"

    }
    @{
      attribute = "full_version"

    }
    @{
      attribute = "external_ip_address"

    }
    @{
      attribute = "hypervisor_types"

    }
    @{
      attribute = "enabled_feature_list"

    }
    @{
      attribute = "management_server_list"

    }
    @{
      attribute = "gpu_driver_version"

    }
    @{
      attribute = "timezone"

    })
  }

  $Headers = @{
    "Authorization" = $AuthHeader.Authorization
    "Force-Refresh" = $true
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/groups"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $Headers
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Get-PC-Clusters BROKEN!!!!!!!!!!!
##################################################################

Function REST-Get-PC-Clusters-V3 {
<#
.SYNOPSIS
Retrieves all Clusters listed in PC. This includes itself, This call is known to be slow / broken in response. Please test beyond 2021.9.x 

.DESCRIPTION
Generic API V3 Cluster query call, retrieves the clusters that are found on this PC. Uses Pagination function to avoid any qyery limit cap.
This API call is known to send delayed responses, if you rename a cluster, it can take several minutes, based on Nutanix Engineering the force refresh parameter is added in the header.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.EXAMPLE
REST-Get-PC-Clusters-V3 `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'14-Jul-21 21:02:13' | INFO  | Building Cluster Query JSON

api_version metadata                         entities
----------- --------                         --------
3.1         @{total_matches=6; kind=cluster} {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; s…  
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [object] $AuthHeader
  )

  Write-Log -message "Building Cluster Query JSON"

  $PsHashPayload = @{
    kind="cluster"
    offset=0
    length=99999
  }

  $Headers = @{
    "Authorization" = $AuthHeader.Authorization
    "Force-Refresh" = $true
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/clusters/list"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $Headers
  }

  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Get PC Cluster Detail
##################################################################

Function REST-Get-PC-Cluster-V3-Detail {
<#
.SYNOPSIS
Pulls the detailed cluster object using the V3 API call.

.DESCRIPTION
Generic API V3 Cluster detail call, strip status for update, returns the defailed PC Cluster object. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster.

.PARAMETER ClusterUuid
ClusterUuid uuid of the cluster to pull detailed info from.

.EXAMPLE
REST-Get-PC-Cluster-V3-Detail `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ClusterUuid $myCluster.metadata.uuid
'16-Oct-21 22:56:44' | INFO  | Pulling Cluster Details '0005aa62-797b-1f9a-6c01-48df37c63270'

status                                             spec                               api_version metadata
------                                             ----                               ----------- --------
@{state=COMPLETE; name=PTSEELM-NXC000; resources=} @{name=PTsddsELM-NXdsa00; resources=} 3.1         @{last_update_time=10/6/2021 4:51:01 PM; kind=cluster; uuid=0005aa62-797b-1f9a-6c01-48df37c63270; spec_version=1; creation_time=10/6/2021 4:51:01 PM; cat…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid
  )

  Write-Log -message "Pulling Cluster Details '$($ClusterUuid)'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/clusters/$($ClusterUuid)"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}


##################################################################
# Update PC Cluster
##################################################################

Function REST-Update-Pc-Cluster-V3-Object {
<#
.SYNOPSIS
Updates the cluster object using the V3 API

.DESCRIPTION
Generic API V3 Cluster Update call, strips status for update.
Use REST-Get-PC-Cluster-V3-Detail to wait for status complete after update has been sent.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PCCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ClusterObj
ClusterObj use REST-Get-PC-Cluster-V3-Detail to pull.

.EXAMPLE
REST-Update-Pc-Cluster-V3-Object `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ClusterObj $clusterDetail
'16-Oct-21 23:06:09' | INFO  | Sending Cluster Object Update.

status                               spec                               api_version metadata
------                               ----                               ----------- --------
@{state=PENDING; execution_context=} @{name=PTSEELM-NXC000; resources=} 3.1         @{last_update_time=10/16/2021 9:03:22 PM; use_categories_mapping=False; kind=cluster; uuid=0005aa62-797b-1f9a-6c01-48df37c63270; spec_version=4; creation_time=10/6/202… 
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [object] $AuthHeader,
    [parameter(mandatory)] [object] $ClusterObj
  )

  $ClusterObj.psobject.members.Remove("Status")

  Write-Log -message "Sending Cluster Object Update."

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/clusters/$($ClusterObj.metadata.uuid)"
    Method               = "PUT"
    Body                 = $ClusterObj
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Get-PC-Login-Token
##################################################################

Function REST-Get-PC-Login-Token {
<#
.SYNOPSIS
Retrieves an auth Cookie from Prism Central

.DESCRIPTION
Uses batch login to retrieve the cookie.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PCCluster IP is the name or IP for the Prism Central Cluster.

.EXAMPLE
REST-Get-PC-Login-Token `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'12-Jul-21 17:41:02' | INFO  | Building PC Batch Login query to get me a token

Comment    :
CommentUri :
HttpOnly   : True
Discard    : False
Domain     : 10.230.88.27
Expired    : False
Expires    : 7/12/2021 5:56:03 PM
Name       : NTNX_IGW_SESSION
Path       : /
Port       :
Secure     : False
TimeStamp  : 7/12/2021 5:41:03 PM
Value      : eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyX3Byb2ZpbGUiOiJ7XCJ1c2VybmFtZVwiOiBcIjEtY2xpY2stbnV0YW5peFwiLCBcImRvbWFpblwiOiBudWxsLCBcImxlZ2FjeV9hZG1pbl9hdXRob3JpdGllc1wiOiBbXCJST0xFX1VTRVJfQURNSU5cIl0sIFwiYXV0aGVudGljYXRlZFwiOiB0cnVlLCBcIl
             9wZXJtYW5lbnRcIjogdHJ1ZSwgXCJsb2dfdXVpZFwiOiBcImU1NTY4YWI4LTg3ZDktNDcyYi1iNzM5LTAwOTRiMDczYTU0ZFwiLCBcInVzZXJ0eXBlXCI6IFwibG9jYWxcIiwgXCJhcHBfZGF0YVwiOiB7fSwgXCJhdXRoX2luZm9cIjoge1widXNlcm5hbWVcIjogXCIxLWNsaWNrLW51dGFuaXhcIiwgXCJyZW1vdGVfY
             XV0aG9yaXphdGlvblwiOiBudWxsLCBcInVzZXJfZ3JvdXBfdXVpZHNcIjogbnVsbCwgXCJyZW1vdGVfYXV0aF9qc29uXCI6IG51bGwsIFwic2VydmljZV9uYW1lXCI6IG51bGwsIFwidG9rZW5fYXVkaWVuY2VcIjogbnVsbCwgXCJ0b2tlbl9pc3N1ZXJcIjogbnVsbCwgXCJ1c2VyX3V1aWRcIjogXCI3NWQwYTY0MS04
             MTI3LTVhN2MtYmM1NC0xYmZmMjRjYThhODNcIiwgXCJ0ZW5hbnRfdXVpZFwiOiBcIjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMFwifX0iLCJqdGkiOiIzYzg2MTJhZS01ZDE4LTRlMTEtODk1Ny1mMGYyNGRlN2FiMGUiLCJpc3MiOiJBdGhlbmEiLCJpYXQiOjE2MjYxMDQ0NjMsImV4cCI6MTYyNjE
             wNTM2M30.q2y8mPeg3Ct9mjTGCR-ht_h1Pl-duk6sOQ3eYHvRbU8Z9ebS-TTqXlwo1SeoHiAldnxxrxmp22IKUq-j7MJ1xkJS2lyBoVhKqQsgiaRViM8d5LaRWHyZsDqRq95W2HcWuPSkTZK-B3Qut1L1vRF0SCWa238tzadYd_gK9TM-bGhA0WcYaxFnbwTB9PAOoqEGs_RFdalnmBkHfWpXrvRudNQDZp6LVmjNt2mNjY
             -jyVPj7s3AYk-sKVqDRdSwSviL_gMdj_c4gfdwJYsJx3CwlZhIEmEcr8ZXaz9V5JYHHq6BJb62R3ZXyrLk7Gg7IjOnB-DfvWJHfsLKR2pKDoY7bA
Version    : 0
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [object] $AuthHeader
  )

  write-log -message "Building PC Batch Login query to get me a token"

  $JsonPayload = @"
{
  "action_on_failure": "CONTINUE",
  "execution_order": "SEQUENTIAL",
  "api_request_list": [{
    "operation": "GET",
    "path_and_params": "/api/nutanix/v3/users/me"
  }, {
    "operation": "GET",
    "path_and_params": "/api/nutanix/v3/users/info"
  }],
  "api_version": "3.0"
}
"@
  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/nutanix/v3/batch"
    Method      = "POST"
    Headers     = $AuthHeader
    Body        = $JsonPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -GetCookies $true `
    -name (Get-FunctionName)

}

##################################################################
# Get-Px-Prim-CurrentUser
##################################################################

Function REST-Get-Px-CurrentUser {
 <#
.SYNOPSIS
Retrieves the current user object from Prism Central or Element

.DESCRIPTION
API V3 user object is returned for the Current Prism User. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PCCluster IP is the name or IP for the Prism Central Cluster.

.EXAMPLE
REST-Get-Px-Prim-CurrentUser `
  -PxClusterIP $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead | fl
'12-Jul-21 17:50:52' | INFO  | Finding Current User

status      : @{state=COMPLETE; name=1-click-nutanix; resources=}
spec        : @{resources=}
api_version : 3.1
metadata    : @{categories_mapping=; kind=user; spec_version=0; uuid=75d0a641-8127-5a7c-bc54-1bff24ca8a83; categories=}
#> 
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )
  Write-Log -message "Finding Current User"

  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/api/nutanix/v3/users/me"
    Method      = "GET"
    Headers     = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Get-Px-Prim-SslCert
##################################################################

Function REST-Get-Px-SslCert {
<#
.SYNOPSIS
Pulls the Current Live SSL Certificate Properties.

.DESCRIPTION
API V1 pem object is returned, used for Certificate Rotation Checking.
Date stamp requires parsing. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.EXAMPLE
REST-Get-Px-SslCert `
  -PxClusterIP $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
 '26-Oct-21 21:41:23' | INFO  | Pulling Prism Certficate for: '10.230.88.26'
 
 countryCode            : SE
 state                  :
 city                   :
 organizationName       : 
 commonName             : asdasd
 organizationalUnitList : {Infrastructure Enginering}
 keyType                : rsa2048
 expiryDate             : Sun Nov 13 09:51:22 CET 2022
 signAlgoName           : SHA256withRSA

#> 
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  Write-Log -message "Pulling Prism Certficate for: '$PxClusterIP'"

  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/keys/pem"
    Method      = "GET"
    Headers     = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Get-Px-Ssh-Keys
##################################################################

Function REST-Get-Px-Ssh-Keys {
 <#
.SYNOPSIS
Retrieves the current SSH Keys from Prism Central or Element

.DESCRIPTION
Retrieves the SSH Keys from the lock down dialog in Prism.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.EXAMPLE
REST-Get-Prim-Ssh-Keys `
  -PxClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'12-Jul-21 17:57:17' | INFO  | Finding Current Keys

name    key
----    ---
Nutanix ssh-rsa abc
Gateway ssh-rsa xyz
#> 
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )
  
  Write-Log -message "Finding Current Keys"

  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/public_keys"
    Method      = "GET"
    Headers     = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Add-Px-Ssh-Keys
##################################################################

Function REST-Add-Px-Ssh-Keys {
<#
.SYNOPSIS
Retrieves the current SSH Keys from Prism Central or Element

.DESCRIPTION
Adds the Keys from the lockdown dialog in Prism.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER Keyname
Keyname is as per listing in Prism

.PARAMETER KeyValue  
KeyValue is a single line string starting with ssh-rsa 

.Lim

.EXAMPLE
REST-Add-Px-Ssh-Keys `
  -PxClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -keyname "Gateway" `
  -KeyValue $MainVars.Creds.Password_Vault.SshPublicKey.secret
'12-Jul-21 18:14:19' | INFO  | Injecting Public Key.

name    key
----    ---
Gateway ssh-rsa XYZ
#> 
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $KeyName,
    [parameter(mandatory)] [string] $KeyValue
  )
  
  write-log -message "Injecting Public Key."
  $PsHashPayload = @{
    "name" = "$($KeyName)"
    "key" = "$($KeyValue)"
  }
  
  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/public_keys"
    Method      = "POST"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Px Virtual Machines API V3
##################################################################

Function REST-Get-Px-VMs-V3 {
<#
.SYNOPSIS
Gets the VM List object, based on API V3.

.DESCRIPTION
Retrieves the Keys from the lockdown dialog in Prism.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.EXAMPLE
REST-Get-Px-v3-VMs `
  -PxClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead |fl
'12-Jul-21 21:23:36' | INFO  | Getting v3 VM List

api_version : 3.1
metadata    : @{total_matches=29; kind=vm; length=29; offset=0}
entities    : {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=;
              spec=; metadata=}…}
#> 
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )
  
  write-log -message "Getting v3 VM List"

  $PsHashPayload = @{
    kind = "vm"
    length = 100
    offset = 0
  }
  
  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/api/nutanix/v3/vms/list"
    Method      = "POST"
    Body        = $PsHashPayload 
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Paginate-Rest  `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Get Px Virtual Machine API V3Detail
##################################################################

Function REST-Get-Px-VMs-V3-Detail {
<#
.SYNOPSIS
Gets the VM Detailed object, based on API V3.

.DESCRIPTION
Retrieves the detailed VM object from Prism Element or Central.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER VmUuid 
VmUuid UUID of the object.

.EXAMPLE
REST-Get-Px-v3-VMs `
  -PxClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead |fl
'12-Jul-21 21:23:36' | INFO  | Getting v3 VM List

api_version : 3.1
metadata    : @{total_matches=29; kind=vm; length=29; offset=0}
entities    : {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=;
              spec=; metadata=}…}

#>  
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmUuid
  )
 
  write-log -message "Getting v3 VM Detail using '$VmUuid'"


  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/api/nutanix/v3/vms/$($VmUuid)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Px Virtual Machine API V2 Detail
##################################################################

Function REST-Get-Px-VM-V2-Detail {
<#
.SYNOPSIS
Gets the VM Detailed object, based on API V2.

.DESCRIPTION
Retrieves the detailed VM object from Prism Element or Central.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER VmUuid 
VmUuid UUID of the object.

.EXAMPLE
REST-Get-Px-VM-V2-Detail `
  -VmUuid '3a05ba8f-0759-460d-bdbe-e7784c72826a' `
  -AuthHeader $Mainvars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PeClusterIP $Mainvars.Cluster.PeClusterIp
'19-Sep-21 15:45:53' | INFO  | Getting v2 VM Detail using '3a05ba8f-0759-460d-bdbe-e7784c72826a'

allow_live_migrate   : True
gpus_assigned        : False
boot                 : @{disk_address=; boot_device_type=disk; uefi_boot=True; secure_boot=False;
                       hardware_virtualization=False}
description          : CCTV
ha_priority          : 0
host_uuid            : 83f6b3b8-267e-4a3c-9060-e1e675e07cd2
memory_mb            : 8192
name                 : xxx
num_cores_per_vcpu   : 1
num_vcpus            : 2
power_state          : on
timezone             : UTC
uuid                 : 3a05ba8f-0759-460d-bdbe-e7784c72826a
vm_disk_info         : {@{disk_address=; is_cdrom=False; is_empty=False; flash_mode_enabled=False;
                       is_scsi_passthrough=True; is_hot_remove_enabled=True; is_thin_provisioned=False; shared=False;
                       source_disk_address=; storage_container_uuid=462fa3bf-e56e-423a-a4b8-3b7a8701a931;
                       size=322122547200; data_source_url=}, @{disk_address=; is_cdrom=False; is_empty=False;
                       flash_mode_enabled=False; is_scsi_passthrough=True; is_hot_remove_enabled=True;
                       is_thin_provisioned=False; shared=False; source_disk_address=;
                       storage_container_uuid=462fa3bf-e56e-423a-a4b8-3b7a8701a931; size=322122547200;
                       data_source_url=}}
vm_features          : @{VGA_CONSOLE=True; AGENT_VM=False}
vm_logical_timestamp : 24
vm_nics              : {@{mac_address=50:6b:8d:e7:14:22; network_uuid=ef7a5d61-f60e-418f-bc18-a91760e22d12;
                       nic_uuid=21fd60ef-a6c2-4f3c-84a0-79403b4022dc; model=; ip_address=xxxx;
                       ip_addresses=System.Object[]; vlan_mode=Access; is_connected=True}}
machine_type         : q35
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmUuid
  )
  
  write-log -message "Getting v2 VM Detail using '$VmUuid'"
  
  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v2.0/vms/$($VmUuid)?include_vm_disk_config=true&include_vm_nic_config=true&includeVMDiskSizes=true&includeAddressAssignments=true"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Delete Pe V2 VM
##################################################################

Function REST-Delete-Px-Vm-V2 {
<#
.SYNOPSIS
Deletes an image from the PC Disk Images store.

.DESCRIPTION
V3 API action. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER Silemt 
Silemt 1, hides any output.

.EXAMPLE
REST-List-Px-Images `
  -PxClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'22-Sep-21 20:26:52' | INFO  | Executing Images List Query

api_version metadata                                             entities
----------- --------                                             --------
3.1         @{total_matches=28; kind=image; length=28; offset=0} {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=…

#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmUuid
  )

  write-log -message "Deleting VM '$vmuuid'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIp):9440/PrismGateway/services/rest/v2.0/vms/$($VmUuid)?delete_snapshots=true"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `

}

##################################################################
# Update Px Virtual Machine API V3 Object
##################################################################

Function REST-Update-Px-VMs-V3-Object {
<#
.SYNOPSIS
Gets the VM Detailed object, based on API V3.

.DESCRIPTION
Retrieves the detailed VM object from Prism Element or Central.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER Vm 
VM object V3 API format. e.g. REST-Get-Px-VMs-V3-Detail

.EXAMPLE
REST-Update-Px-VMs-V3-Object `
  -PxClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -VM $Vm
'10-Aug-21 16:51:13' | INFO  | Stripping Status

status                               spec                                                     api_version metadata
------                               ----                                                     ----------- --------
@{state=PENDING; execution_context=} @{name=POSSE445-NT8050.; resources=; cluster_reference=} 3.1         @{last_update_time=4/13/2021 8:59:43 AM; use_categories_mapping=False; kind=vm; uuid=e865b142-6f9b-4e9c-a4c1-9e565a8cbc2c; project_reference=; sp…
#>   
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $Vm
  )

  Write-Log -message "Stripping Status"

  $VM.psobject.members.Remove("Status")


  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/api/nutanix/v3/vms/$($vm.metadata.uuid)"
    #Uri         = "https://$($PxClusterIP):9440/api/nutanix/v3/vms/$($vm.cluster_reference.uuid)" 
    Method      = "PUT"
    Body        = $Vm
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# VM Group Call
##################################################################

Function REST-Query-Pc-Vms-Group {
<#
.SYNOPSIS
Gets a PC VM List based on an API v3 Group call.

.DESCRIPTION
Group Calls are unreadable for human eyes. They require reconstructing of a meaningful object.
They are however in some cases more reliable than a normal VM V1/2/3 call.
Navigate the group results to reconstruct a meaningful object.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER Vm 
VM object V3 API format. e.g. REST-Get-Px-VMs-V3-Detail

.EXAMPLE
REST-Query-Pc-Vms-Group -PcClusterIp 10.230.88.27 -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead

entity_type           : mh_vm
filtered_entity_count : 38
filtered_group_count  : 1
group_results         : {@{entity_results=System.Object[]; group_by_column_value=; group_summaries=; total_entity_count=38}}
total_entity_count    : 44
total_group_count     : 1

#> 
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )
  $PsHashPayload = @{
    entity_type = "mh_vm"
    query_name = (new-guid).guid
    grouping_attribute = " "
    group_count = 3
    group_offset = 0
    group_attributes = @()
    group_member_count = 10000
    group_member_offset = 0
    group_member_sort_attribute = "vm_name"
    group_member_sort_order = "ASCENDING"
    group_member_attributes = @(
      @{
        attribute = "vm_name"
      }
      @{
        attribute = "node_name"
      }
      @{
        attribute = "project_name"
      }
      @{
        attribute = "owner_username"
      }
      @{
        attribute = "hypervisor_type"
      }
      @{
        attribute = "memory_size_bytes"
      }
      @{
        attribute = "ip_addresses"
      }
      @{
        attribute = "power_state"
      }
      @{
        attribute = "ngt.installed_version"
      }
      @{
        attribute = "cluster_name"
      }
      @{
        attribute = "project_reference"
      }
      @{
        attribute = "owner_reference"
      }
      @{
        attribute = "categories"
      }
      @{
        attribute = "cluster"
      }
      @{
        attribute = "state"
      }
      @{
        attribute = "message"
      }
      @{
        attribute = "reason"
      }
      @{
        attribute = "is_cvm"
      }
      @{
        attribute = "is_acropolis_vm"
      }
      @{
        attribute = "num_vcpus"
      }
      @{
        attribute = "is_live_migratable"
      }
      @{
        attribute = "gpus_in_use"
      }
      @{
        attribute = "network_security_rule_id_list"
      }
      @{
        attribute = "zone_type"
      }
      @{
        attribute = "vm_annotation"
      }
      @{
        attribute = "vm_type"
      }
      @{
        attribute = "capacity.policy_anomaly_detail"
      }
      @{
        attribute = "capacity.policy_efficiency_detail"
      }
      @{
        attribute = "protection_type"
      }
      @{
        attribute = "guest_os_name"
      }
      @{
        attribute = "ngt.guest_os"
      }
      @{
        attribute = "ngt.enabled_applications"
      }
      @{
        attribute = "ngt.cluster_version"
      }
      @{
        attribute = "protection_policy_state"
      }
      @{
        attribute = "recovery_plan_state_list"
      }
    )
    filter_criteria = "(platform_type!=aws,platform_type==[no_val]);is_cvm==0"
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/groups"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Create Pc Virtual Machine API V3
##################################################################

Function REST-Create-Pc-Vm-V3 {
<#
.SYNOPSIS
Creates a Prism VM using the V3 API, compatible with Pc only, due to Project Reference

.DESCRIPTION
Extensive API call to create a Prism VM, This includes projects and therefore PC only.
Read each parameter clearly to understand the required input. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER ClusterUUID 
ClusterUUID is the remote cluster UUID, used for PC Proxy Command

.PARAMETER CpuThreads 
CpuThreads number of threads per core, integer

.PARAMETER CpusPerSocket
CpusPerSocket number of cores per sockets, integer

.PARAMETER CpuSockets 
CpuSockets number of sockets, integer

.PARAMETER BootMode
Bootmode '0' means legacy boot, '1' means uefi only boot, '2' means secure boot, '3' means secure boot with credential guard

.PARAMETER MemoryMB  
MemoryMB Memory for the VM in Megabytes, integer

.PARAMETER VmName
VmName name of the Virtual Machine

.PARAMETER SubnetUuid 
SubnetUuid uuid of the subnet for the primary interface for this VM.

.PARAMETER SubnetName 
SubnetName name of the subnet for the primary interface for this VM.

.PARAMETER DiskMB 
DiskMB number of megabytes for the first disk it size.

.PARAMETER ContainerUuid   
ContainerUuid UUID of the container the vm needs to be added towards.

.PARAMETER ContainerName
ContainerName Name of the container the vm needs to be added towards.

.PARAMETER ImageUuid
ImageUuid UUID of the Image that's cloned for the primary disk of this VM.

.PARAMETER ProjectName  
ProjectName name of the project that this VM needs to be added towards (PC only.)

.PARAMETER ProjectUuid
ProjectUuid Uuid of the project that this VM needs to be added towards (PC only.)

.PARAMETER ClusterUuid  
ClusterUuid Uuid of the cluster that this VM needs to be added towards (PC only.)

.PARAMETER ClusterName  
ClusterName Name of the cluster that this VM needs to be added towards (PC only.)

.PARAMETER OwnerName
OwnerName Name of the owner that this VM needs to be added towards (PC only.)

.PARAMETER OwnerUuid
OwnerUuid UUid of the owner that this VM needs to be added towards (PC only.)

.PARAMETER GuestOSCustomizeScript
GuestOSCustomizeScript Set to NONE if not required. Script file that needs to be added. (its contents as multiline here string)

.PARAMETER GuestOSType
GuestOSType Windows or Linux only used for determing the method of Guest Customization. Linux is default.

.PARAMETER GpuProfileVendor
GpuProfileVendor Vendor of the GPU Profile, if not required, make sure GpuProfileDeviceName is "NONE"

.PARAMETER DiskType 
DiskType SATA or SCSI, SCSI Is the automatic default. 

.PARAMETER GpuProfileDeviceType
GpuProfileDeviceType Type of the GPU Profile, VIRTUAL or PASSTHROUGH, if not required, make sure GpuProfileDeviceName is "NONE" Use REST-Get-Prx-Gpu-Profiles to get the profiles for a cluster

.PARAMETER GpuProfileDeviceId
GpuProfileDeviceId Id of the GPU Profile usually a 3 digit nr., if not required, make sure GpuProfileDeviceName is "NONE" Use REST-Get-Prx-Gpu-Profiles to get the profiles for a cluster

.PARAMETER GpuProfileDeviceName
GpuProfileDeviceName Name of the GPU Profile. If not required, make sure Value is "NONE" Use REST-Get-Prx-Gpu-Profiles to get the profiles for a cluster

.EXAMPLE 
PS C:\Program Files\PowerShell\7> REST-Create-Pc-Vm-V3 `
>>   -PcClusterIp 1.1.1.1 `
>>   -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
>>   -CpuThreads 1 `
>>   -CpusPerSocket 1 `
>>   -CpuSockets 1 `
>>   -MemoryMB 4096 `
>>   -VmName TestVMMies `
>>   -SubnetUuid ef7a5d61-f60e-418f-bc18-a91760e22d12 `
>>   -SubnetName RETSE124-104-Servers `
>>   -DiskMB 60000 `
>>   -ContainerUuid "462fa3bf-e56e-423a-a4b8-3b7a8701a931" `
>>   -ContainerName SelfServiceContainer `
>>   -ImageUuid eeaa5368-0252-460e-9e13-9fad9daf655a `
>>   -ProjectName xxxx-xxx `
>>   -ProjectUuid c2cb2158-848b-46d2-b562-0040a723fcc3 `
>>   -ClusterUuid 0005ba33-a0b7-8458-0548-48df37c60a60 `
>>   -ClusterName xx-xxx `
>>   -OwnerName michell.grauwmans@xxxx.com `
>>   -OwnerUuid 618c57fe-c221-51bb-842e-75f15b163016 `
>>   -GpuProfileVendor "NONE" `
>>   -GuestOSType "Windows"
>>   -GpuProfileDeviceType "NONE" `
>>   -GpuProfileDeviceId "NONE" `
>>   -GpuProfileDeviceName "NONE" `
>>   -AosVersion 5.20.0.1 `
>>   -DiskType SCSI `
>>   -DisableCdRom $false `
>>   -GuestOSCustomizeScript "NONE"
'30-Dec-21 19:47:56' | INFO  | Creating VM using 'v3' spec PC: 'x.x.x.x'
'30-Dec-21 19:47:56' | INFO  | CPU Threads                   : '1'
'30-Dec-21 19:47:56' | INFO  | CPU Per Socket                : '1'
'30-Dec-21 19:47:56' | INFO  | CPU Sockets                   : '1'
'30-Dec-21 19:47:56' | INFO  | RAM MB                        : '4096'
'30-Dec-21 19:47:56' | INFO  | VM Name                       : 'TestVMMies'
'30-Dec-21 19:47:56' | INFO  | Disk Size MB                  : '60000'
'30-Dec-21 19:47:56' | INFO  | Subnet Name                   : 'xx-xx-xx'
'30-Dec-21 19:47:56' | INFO  | Subnet Uuid                   : 'ef7a5d61-f60e-418f-bc18-a91760e22d12'
'30-Dec-21 19:47:56' | INFO  | Container Uuid                : '462fa3bf-e56e-423a-a4b8-3b7a8701a931'
'30-Dec-21 19:47:56' | INFO  | Container Name                : 'SelfServiceContainer'
'30-Dec-21 19:47:56' | INFO  | Image Uuid                    : 'eeaa5368-0252-460e-9e13-9fad9daf655a'
'30-Dec-21 19:47:56' | INFO  | Project Uuid                  : 'c2cb2158-848b-46d2-b562-0040a723fcc3'
'30-Dec-21 19:47:56' | INFO  | Project Name                  : 'xxx-xx'
'30-Dec-21 19:47:56' | INFO  | Cluster Uuid                  : '0005ba33-a0b7-8458-0548-48df37c60a60'
'30-Dec-21 19:47:56' | INFO  | Cluster Name                  : 'xx-xx'
'30-Dec-21 19:47:56' | INFO  | Owner Uuid                    : '618c57fe-c221-51bb-842e-75f15b163016'
'30-Dec-21 19:47:56' | INFO  | Owner Name                    : 'michell.grauwmans@xx.com'
'30-Dec-21 19:47:56' | INFO  | Aos Version                   : '5.20.0.1'
'30-Dec-21 19:47:56' | INFO  | Gpu Profile Name              : 'NONE'

status                               spec                                               api_version metadata
------                               ----                                               ----------- --------
@{state=PENDING; execution_context=} @{name=TestVMMies; resources=; cluster_reference=} 3.1         @{use_categories_mapping=False; kind=vm; uuid=ef043bf8-464c-4d00-8646-d2f3c…


#>
  Param (
    [parameter(mandatory)] [string]  $PcClusterIp,
    [parameter(mandatory)] [Object]  $AuthHeader,
                           [int]     $CpuThreads    = 1,
                           [int]     $CpusPerSocket = 1,
                           [int]     $CpuSockets    = 1,
                           [int]     $MemoryMB      = 4096,
    [parameter(mandatory)] [string]  $VmName,
                           [int]     $BootMode = 0,
    [parameter(mandatory)] [string]  $SubnetUuid,
    [parameter(mandatory)] [string]  $SubnetName,
    [parameter(mandatory)] [int64]   $DiskMB,
    [parameter(mandatory)] [string]  $ContainerUuid,
                           [string]  $ContainerName = "SelfServiceContainer",
    [parameter(mandatory)] [string]  $ImageUuid,
    [parameter(mandatory)] [string]  $GuestOSType = "Linux",
    [parameter(mandatory)] [string]  $ProjectName,
    [parameter(mandatory)] [string]  $ProjectUuid,
    [parameter(mandatory)] [string]  $ClusterUuid,
    [parameter(mandatory)] [string]  $ClusterName,
    [parameter(mandatory)] [String]  $OwnerName,
    [parameter(mandatory)] [string]  $OwnerUuid,
    [parameter(mandatory)] [string]  $GuestOSCustomizeScript,
    [parameter(mandatory)] [String]  $GpuProfileVendor,
    [parameter(mandatory)] [string]  $GpuProfileDeviceType,
    [parameter(mandatory)] [string]  $GpuProfileDeviceId,
    [parameter(mandatory)] [string]  $GpuProfileDeviceName,
    [parameter(mandatory)] [Version] $AosVersion,
                           [string]  $DiskType = "SCSI",
                           [bool]    $DisableCdRom = $false
  )

  if ($disktype -ne "SATA"){
    $DiskType = "SCSI"
  }

  Switch ($BootMode){
    0 {$BootType = "LEGACY"      ; $MachineType = "PC" ; $HardwareVirtualization = $false}
    1 {$BootType = "SECURE_BOOT" ; $MachineType = "Q35"; $HardwareVirtualization = $false}
    2 {$BootType = "SECURE_BOOT" ; $MachineType = "Q35"; $HardwareVirtualization = $false}
    3 {$BootType = "SECURE_BOOT" ; $MachineType = "Q35"; $HardwareVirtualization = $true}
  }

  write-log -message "BootMode: '0' means legacy boot."
  write-log -message "BootMode: '1' means uefi only boot."
  write-log -message "BootMode: '2' means secure boot."
  write-log -message "BootMode: '3' means secure boot with credential guard (warning, no live migration in AOS 5.20.x)"
  write-log -message "Current BootMode: '$BootMode'"
  write-log -message "Creating VM using 'v3' spec PC: '$PcClusterIp'"
  write-log -message "CPU Threads                   : '$CpuThreads'" -d 2
  write-log -message "CPU Per Socket                : '$CpusPerSocket'" -d 2
  write-log -message "CPU Sockets                   : '$CpuSockets'" -d 2
  write-log -message "RAM MB                        : '$MemoryMB'" -d 2
  write-log -message "VM Name                       : '$VmName'" 
  write-log -message "Disk Size MB                  : '$DiskMB'" -d 2
  write-log -message "Subnet Name                   : '$SubnetName'" 
  write-log -message "Subnet Uuid                   : '$SubnetUuid'" -d 2
  write-log -message "Container Uuid                : '$ContainerUuid'" -d 2
  write-log -message "Container Name                : '$ContainerName'" -d 2
  write-log -message "Guest OS Type                 : '$GuestOSType'" -d 2
  write-log -message "Image Uuid                    : '$ImageUuid'" -d 2
  write-log -message "Project Uuid                  : '$ProjectUuid'" -d 2
  write-log -message "Project Name                  : '$ProjectName'" -d 2
  write-log -message "Cluster Uuid                  : '$ClusterUuid'" -d 2
  write-log -message "Cluster Name                  : '$ClusterName'" -d 2
  write-log -message "Owner Uuid                    : '$OwnerUuid'" -d 2
  write-log -message "Owner Name                    : '$OwnerName'" -d 2 
  write-log -message "Aos Version                   : '$($AosVersion)'" -d 2
  write-log -message "Gpu Profile Name              : '$($GpuProfileDeviceName)'" -d 2 

  [int64]$DiskBytes = $DiskMB * 1024 * 1024


  $PsHashPayload = @{
    spec = @{
      name = $VmName
      resources = @{
        num_threads_per_core = $CpuThreads
        vnuma_config = @{
          num_vnuma_nodes = 0
        }
        serial_port_list = @()
        hardware_virtualization_enabled = $HardwareVirtualization
        num_vcpus_per_socket = $CpusPerSocket
        nic_list = @(
          @{
            nic_type = "NORMAL_NIC"
            ip_endpoint_list = @()
            vlan_mode = "ACCESS"
            subnet_reference = @{
              kind = "subnet"
              name = $SubnetName
              uuid = $SubnetUuid
            }
            is_connected = $true
            trunked_vlan_list = @()
          }
        )
        num_sockets = $CpuSockets
        disable_branding = $false
        enable_cpu_passthrough = $false
        gpu_list = @()
        is_agent_vm = $false
        memory_size_mib = $MemoryMB
        boot_config = @{
          boot_type = $BootType
          boot_device = @{
            disk_address = @{
              device_index = 0
              adapter_type = $DiskType
            }
          }        
        }

        hardware_clock_timezone = "CET"
        guest_customization = @{}
        power_state_mechanism = @{}
        power_state = "OFF"
        machine_type = $MachineType
        vga_console_enabled = $true
        disk_list = @(
          @{
            device_properties = @{
              disk_address = @{
                device_index = 1
                adapter_type = "SATA"
              }
              device_type = "CDROM"
            }
          }
          @{
            disk_size_bytes = $DiskBytes
            storage_config = @{
              storage_container_reference =@{
                kind = "storage_container"
                uuid = $ContainerUuid
                name = $ContainerName
              }
            }
            device_properties = @{
              disk_address = @{
                device_index = 0
                adapter_type = $DiskType
              }
              device_type = "DISK"
            }
            data_source_reference = @{
              kind = "image"
              uuid = $ImageUuid
            }
          }
        )
      }
      cluster_reference = @{
        kind = "cluster"
        name = $ClusterName
        uuid = $ClusterUuid
      }
    }
    api_version = "3.1"
    metadata = @{
      kind = "vm"
      project_reference = @{
        kind = "project"
        name = $ProjectName
        uuid = $ProjectUuid
      }
      categories_mapping = @{}
      categories = @{}
      owner_reference = @{
        kind = "user"
        name = $OwnerName
        uuid = $OwnerUuid
      }
    }
  }

  if($DisableCdRom){

    write-log -message "No CDROM Drive..." -d 2

    [array]$PsHashPayload.spec.resources.disk_list = $PsHashPayload.spec.resources.disk_list | where {$_.device_properties.device_type -ne "CDROM"}

  }

  if ($GuestOSCustomizeScript -ne "NONE"){

    write-log -message "Adding Guest Customization." -d 2

    if ($Debug -ge 2){
      write $GuestOSCustomizeScript | out-file c:\temp\Oscust.yaml
    }
    $GuestOSCustomizeScriptBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($GuestOSCustomizeScript))
  
    write-log -message "Construncting payload." -d 2

    if ($GuestOSType -match "^Lin"){

      write-log -message "Using Linux, Cloud Init Guest Customization"

      $GuestCust = @{
        guest_customization = @{
          cloud_init = @{
            user_data = $GuestOSCustomizeScriptBase64
          }
        }
      }

    } else {

      write-log -message "Using Windows, Sysprep Guest Customization"

      $GuestCust = @{
        guest_customization = @{
          sysprep = @{
            unattend_xml = $GuestOSCustomizeScriptBase64
          }
        }
      }
    }
  
    write-log -message "Merging Payload." -d 2
    write-log -message "Pre Payload: '$($GuestCust.guest_customization.cloud_init.user_data)'" -d 2

    $PsHashPayload.spec.resources.guest_customization = $GuestCust.guest_customization

    write-log -message "Post Payload: '$($PsHashPayload.spec.resources.guest_customization.cloud_init.user_data)'" -d 2

  } else {

    write-log -message "Removing guest Customization"

    $PsHashPayload.spec.resources.Remove('guest_customization')

  }
  if ($GpuProfileDeviceName -ne "NONE"){

    write-log -message "Adding GPU Object, device ID  : '$($GpuProfileDeviceId)'"

    $GpuProfileObj = @{
      gpu_list = @(@{
        vendor = $GpuProfileVendor
        mode = $GpuProfileDeviceType
        device_id = [int]$GpuProfileDeviceId
      })
    }  
    $PsHashPayload.spec.resources.gpu_list += $GpuProfileObj.gpu_list
  }

  if ($Debug -ge 2){
    $PsHashPayload | convertto-json -depth 99 | out-file c:\temp\VMPayload.json
  }

  write-log -message "Post Payload Last: '$($PsHashPayload.spec.resources.guest_customization.cloud_init.user_data)'" -d 2

  if ($AosVersion -lt [version]"5.19.1.5"){

    write-log -message "Removing Virt Tech Param with older AOS Versions." -sev "WARN" -Errorcode "UNDEFINED"

    $PsHashPayload.spec.resources.Remove('hardware_virtualization_enabled')
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/vms"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Get Pe VM List
##################################################################

Function REST-Get-Pe-VMs-V1 {
<#
.SYNOPSIS
Gets the VM List, based on API V1.

.DESCRIPTION
Retrieves the API V1 list from Prism Element.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIP 
PeCluster IP is the name or IP for the Prism Element

.EXAMPLE
REST-Get-Pe-VMs-V1 `
  -PEClusterIP $MainVars.Cluster.PEClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead | fl
'30-Dec-21 19:50:00' | INFO  | Executing VM List

metadata : @{grandTotalEntities=36; totalEntities=36; filterCriteria=; sortCriteria=; page=1; count=36; startIndex=1; endIndex=36}
entities : {@{vmId=0005ba33-a0b7-8458-0548-48df37c60a60::0dc563c9-8405-4ac8-9f1d-bf1ed3841a3f; uuid=0dc563c9-8405-4ac8-9f1d-bf1ed3841a3f; powerState=on;
           vmName=}
#> 
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [bool]   $silent = $false
  ) 
  if (!$silent){

    Write-Log -message "Executing VM List"

  }

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/vms"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Upload-Px-Certificates
##################################################################

Function REST-Upload-Px-Certificates {
<#
.SYNOPSIS
Uploads a certificate to the prism UI via REST API

.DESCRIPTION
Uploads 3 certificate files to the prism UI based SSL Certificate page.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER CertFileName  
CertFileName is the public certificate file, just filename, excluding path.

.PARAMETER KeyFilename  
KeyFilename is the Private Key File Name, just filename, excluding path.

.PARAMETER ChainFilename
ChainFilename is the certificate trust chain, just filename, excluding path.

.PARAMETER KeyType
Key type the the cypher for the key.

.PARAMETER Path
Full base path that holds the certificate files, has to be the same path for all files. Excluding trailing slash. 

.EXAMPLE
REST-Upload-Px-Certificates `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PxClusterIP $MainVars.Cluster.PeClusterIp `
  -path "$($MainVars.MetaData.DaemonDir)\Certificates" `
  -CertFileName "prism.cer" `
  -KeyFileName "prism.pem" `
  -ChainFileName "chain.crt" `
  -KeyType "RSA_2048"
 '12-Jul-21 22:20:45' | INFO  | Uploading / Installing Certificates
 
 name     :
 keyType  : RSA_2048
 password :
 key      : GHI
 cert     : DEF
 caChain  : ABC
#>  
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $Path,
    [parameter(mandatory)] [string] $CertFileName = "prism.cer",
    [parameter(mandatory)] [string] $KeyFileName = "prism.pem",
    [parameter(mandatory)] [string] $ChainFileName ="chain.crt",
    [parameter(mandatory)] [string] $KeyType = "RSA_2048"
  )
 
  $Form = @{
      keyType    = "RSA_2048"
      key        = Get-Item -Path "$($Path)\$($KeyFileName)"
      cert       = Get-Item -Path "$($Path)\$($CertFileName)"
      caChain    = Get-Item -Path "$($Path)\$($ChainFileName)"
  }

  write-log -message "Uploading / Installing Certificates"
  
  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/keys/pem/import"
    Method      = "POST"
    Form        = $Form
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get-Px-User
##################################################################

Function REST-Get-Px-Users {
<#
.SYNOPSIS
Gets the users of a Prism element or Central local user.

.DESCRIPTION

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.EXAMPLE
REST-Get-Px-Users `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'27-Oct-21 00:40:49' | INFO  | Pulling users: '10.230.88.26'

profile             : @{username=admin; firstName=; middleInitial=; lastName=; emailId=; password=; locale=en-US; region=en-US; ldapLoginName=}
roles               : {ROLE_CLUSTER_ADMIN, ROLE_USER_ADMIN, ROLE_CLUSTER_VIEWER}
enabled             : True
creationTimeUsecs   : 1594714863658
lastAccessTimeUsecs : 0
lastUpdatedByUser   : admin

profile             : @{username=1-click-robo; firstName=svc; middleInitial=; lastName=robo; emailId=1-click-robo@xxx.com; password=; locale=en-US; region=en-US; ldapLoginName=}
roles               : {ROLE_CLUSTER_ADMIN, ROLE_USER_ADMIN, ROLE_CLUSTER_VIEWER}
enabled             : True
creationTimeUsecs   : 1599159983294000
lastAccessTimeUsecs : 0
lastUpdatedByUser   : admin

profile             : @{username=1-click-nutanix; firstName=svc; middleInitial=; lastName=nutanix; emailId=1-click-xxx@xxx.com; password=; locale=en-US; region=en-US; ldapLoginName=}
roles               : {ROLE_CLUSTER_ADMIN, ROLE_USER_ADMIN, ROLE_CLUSTER_VIEWER}
enabled             : True
creationTimeUsecs   : 1615455048370000
lastAccessTimeUsecs : 0
lastUpdatedByUser   : migra6

#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )   
  write-log -message "Pulling users: '$PxClusterIP'"
  
  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/users"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 



##################################################################
# Reset-Px-User
##################################################################

Function REST-Reset-Px-User {
<#
.SYNOPSIS
Resets the password of a Prism element or Central local user.

.DESCRIPTION
Must
Contain at least 8 character(s)
Contain at least 1 lowercase character(s)
Contain at least 1 uppercase character(s)
Contain at least 1 digit(s)
Contain at least 1 special character(s)
Differ by at least 4 character(s) from your previous password
Not be the same as your 5 most recent password(s)
Not have more than 2 consecutive characters be the same
Contain at least 4 of the following 4 character classes: uppercase letters, lowercase letters, digits, and special characters
Not be a simple word, or a word found in the dictionary

HTTP 500 if the user does not exist.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIP 
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER TargetUser
Target user is the target username :)

.PARAMETER TargetPass
Target pass is the target password

.EXAMPLE
REST-Reset-Px-User `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -PxClusterIP $MainVars.AutoDc.PcClusterIp `
  -TargetUser MMouse `
  -TargetPass "YouWishThisWasTrue01!%423342123weq"
'12-Jul-21 23:01:16' | INFO  | Resetting user: 'MMouse'

value
-----
 True
#>   
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $TargetUser,
    [parameter(mandatory)] [string] $TargetPass
  )

  write-log -message "Resetting user: '$targetuser'"
  
  $PsHashPayload = @{
    "username" = "$($TargetUser)"
    "password" = "$($TargetPass)"
  }
  
  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/users/reset_password"
    Method      = "POST"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Category-Value-Create
##################################################################

Function REST-Create-Pc-Category-Value {
<#
.SYNOPSIS
Creates a value for a category, requires the Category object as input, see Rest-Get-Pc-Category

.DESCRIPTION
Creates the value object for a given category object. Categories only exist on PC.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER CatObj 
CatObj see function Rest-Get-Pc-Category

.PARAMETER Value
Value string value for category, must not exist.

.EXAMPLE
REST-Category-Pc-Value-Create `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Catobj $CatObj `
  -Value Test
'13-Jul-21 07:45:42' | INFO  | Creating Value 'Test' on Category 'App_Type'

system_defined name     value description
-------------- ----     ----- -----------
         False App_Type Test  Created by MMouse.
#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $CatObj,
    [parameter(mandatory)] [string] $Value
  )

  Write-Log -message "Creating Value '$Value' on Category '$($CatObj.name)'"

  $PsHashPayload = @{
    "value"       = "$($Value)"
    "description" = "$($CatObj.description)"
  }
  
  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/nutanix/v3/categories/$($CatObj.name)/$($Value)"
    Method      = "PUT"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Category-Create
##################################################################

Function REST-Create-Pc-Category {
<#
.SYNOPSIS
Creates  a category in PC

.DESCRIPTION
Creates the value object for a given category object.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER Name
Name of the category to create, use REST-Query-Pc-Category to check if exists.

.EXAMPLE
REST-Create-Pc-Category `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Name "BLAAT"
'15-Jul-21 10:04:23' | INFO  | Creating / Updating Category 'BLAAT'

system_defined name  capabilities      description
-------------- ----  ------------      -----------
         False BLAAT @{cardinality=64} Created by 1-click-Nutanix.
#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $Name
  )


  Write-Log -message "Creating / Updating Category '$($Name)'"

  $PsHashPayload = @{
    "api_version"  = "3.1.0"
    "description"  = "Created by BP Autonomics."
    "capabilities" = @{"cardinality" = 64}
    "name"         = "$($Name)"
  }

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/nutanix/v3/categories/$($Name)"
    Method      = "PUT"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Category-Query
##################################################################

Function REST-Query-Pc-Category {
 <#
.SYNOPSIS
Retrieves the category from PC

.DESCRIPTION
Returns an error if not exist, Error is suppressed.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER Name
Name of the category to query.

.EXAMPLE
REST-Query-Pc-Category `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Name "BLAAT"
'15-Jul-21 10:04:23' | INFO  | Creating / Updating Category 'BLAAT'

system_defined name  capabilities      description
-------------- ----  ------------      -----------
         False BLAAT @{cardinality=64} Created by 1-click-Nutanix.
#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $Name
  )

  Write-Log -message "Finding Category with Name '$($Name)'"

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/nutanix/v3/categories/$($Name)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName) `
    -Retry 0 `
    -LastError $false

  Return $task
} 

##################################################################
# Get Protection Domains
##################################################################

Function REST-Get-Prx-ProtectionDomains {
<#
.SYNOPSIS
Retrieves the category from PC

.DESCRIPTION
Returns a v1 list object from the protection domains

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ClusterUUID
ClusterUUID UUID String from the target cluster, will return nothing if UUID is bad.

.EXAMPLE
REST-Get-Prx-ProtectionDomains `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ClusterUUID $uuid
'17-Jul-21 12:53:35' | INFO  | Executing Remote PD List from PE Cluster '0005aa62-797b-1f9a-6c01-48df37c63270'

name                    : xxxx-Silver_CCG
......
#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUUID
  )

  write-log -message "Executing Remote PD List from PE Cluster '$($ClusterUUID)'"

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/protection_domains?metroAvail=false&projection=stats%2Calerts&proxyClusterUuid=$($ClusterUUID)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Query PC AD Groups
##################################################################

Function REST-Query-Pc-AD-Groups {
<#
.SYNOPSIS
Retrieves Ad Groups from Pc, only which have an object ID

.DESCRIPTION
API v3 based group query, used for retrieving the PC object uuids for a group. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.EXAMPLE
REST-Query-Pc-AD-Groups -PcClusterIp 10.230.88.27 -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead
'17-Jul-21 12:25:11' | INFO  | Building UserGroup Query JSON

api_version metadata                                                  entities
----------- --------                                                  --------
3.1         @{total_matches=14; kind=user_group; length=14; offset=0} {@{status=; spec=; metadata=}, @{status=; spec=;…
#> 
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )
 
  write-log -message "Building UserGroup Query JSON"

  $PsHashPayload= @{
    kind="user_group"
    offset=0
    length=9999
  } 

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/nutanix/v3/user_groups/list"
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Create PC AD Group object
##################################################################

Function REST-Create-Pc-Ad-GroupObject {
<#
.SYNOPSIS
Creates a PC Object for  Ad Groups from Pc

.DESCRIPTION
API v3 based group create, please test if exists first.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.EXAMPLE
REST-Create-Pc-Ad-GroupObject `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -GroupName $GroupCN `
  -GroupDn $GroupDN
'24-Aug-21 12:42:17' | INFO  | Building UserGroup Create for group 'CN-XYZ'
'24-Aug-21 12:42:17' | INFO  | API Query to create a group object for DN: 'DNXYZ'

status                               spec          api_version metadata
------                               ----          ----------- --------
@{state=PENDING; execution_context=} @{resources=} 3.1         @{use_categories_mapping=False; kind=user_group; name=U…
#> 
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $GroupDn,
    [parameter(mandatory)] [string] $GroupName
  )

  write-log -message "Building UserGroup Create for group '$GroupName'"
  write-log -message "API Query to create a group object for DN: '$($GroupDn)'"

  $PsHashPayload= @{
    spec = @{
      resources = @{
        directory_service_user_group = @{
          distinguished_name = $GroupDn
        }
      }
    }
    api_version ="3.1.0"
    metadata = @{
      kind = "user_group"
      categories = @{}
      name = $GroupName
    }
  } 

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/nutanix/v3/user_groups"
    Method      = "Post"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get HA Reservation Status
##################################################################

Function REST-Get-Pe-HA-Status {
<#
.SYNOPSIS
Retrieves HA Status from Prism Element

.DESCRIPTION
API v0.8 based returns the HA Object, numHostFailuresToTolerate 0 means HA reservation is disabled in the UI, numHostFailuresToTolerate 1 means its enabled..

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element Cluster.

.EXAMPLE
REST-Get-Pe-HA-Status -PeClusterIP $MainVars.Cluster.PeClusterIP -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'17-Jul-21 13:16:09' | INFO  | Retrieving HA Status

failoverEnabled             : True
numHostFailuresToTolerate   : 0
reservationType             : NoReservations
logicalTimestamp            : 0
reservedHostUuids           :
failoverInProgressHostUuids :
haState                     : BestEffort
#>  
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Retrieving HA Status"

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/api/nutanix/v0.8/ha"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Set HA Reservation Status
##################################################################

Function REST-Enable-Pe-HA-Status {
<#
.SYNOPSIS
Retrieves HA Status from Prism Element

.DESCRIPTION
API v0.8 based enables the HA Reservation, numHostFailuresToTolerate 0 means HA reservation is disabled in the UI, numHostFailuresToTolerate 1 means its enabled..
Output is the task UUID created for the action, can be traced with the task progress monitor. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element Cluster.

.EXAMPLE
REST-Enable-Pe-HA-Status `
  -PeClusterIP $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'17-Jul-21 13:26:55' | INFO  | Enabling HA Reservation Status

taskUuid
--------
41049474-534e-416c-87e1-15b93089a525
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload= @{
    enableFailover = $true
    numHostFailuresToTolerate = 1
  } 

  write-log -message "Enabling HA Reservation Status"

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/api/nutanix/v0.8/ha"
    Method      = "PUT"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add Pe Witness
##################################################################

Function REST-Add-Pe-Witness {
<#
.SYNOPSIS
Sets the witness in Prism Element, get does not exist. Only set on metro capable or 2 nodes.

.DESCRIPTION
API v2.0 based response.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element Cluster.

.PARAMETER WitnessPassword
WitnessPassword, password of the witness admin user. Username is hard coded.

.PARAMETER WitnessIP
WitnessIP, IP address of the witness to configure.

.PARAMETER Clustername
Clustername, the Prism Cluster name

.EXAMPLE

Untested...(Tested in old methods)
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $WitnessPassword,
    [parameter(mandatory)] [string] $WitnessIP,
    [parameter(mandatory)] [string] $ClusterName
  )

  $PsHashPayload= @{
    ip_addresses = @($($WitnessIP))
    username = "admin"
    password = $WitnessPasswor
    cluster_name = $ClusterName
  } 

  write-log -message "Registering Witness '$WitnessIP'"

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v2.0/cluster/metro_witness"
    Method      = "POST"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Px Ntp Servers 
##################################################################

Function REST-Get-Px-NtpServers {
<#
.SYNOPSIS
Retrieves the list of current NTP servers, works with PE and PC

.DESCRIPTION
API v1.0 based response. Array of NTP servers

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.EXAMPLE
REST-Get-Px-NTP `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $AuthHeader
  '17-Jul-21 14:14:43' | INFO  | Retrieving NTP Servers
  ntp1-xxxxx
  ntp2-xxxxx
  ntp1-xxxxx
  ntp1-xxxxx
  ntp1-xxxxx
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Retrieving NTP Servers"

  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/ntp_servers"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName) `
    -LastError $false `
    -Retry 0
} 

##################################################################
# Remove Px Ntp Servers 
##################################################################

Function REST-Remove-Px-NtpServers {
<#
.SYNOPSIS
Removes the array list of specified NTP servers, works with PE and PC

.DESCRIPTION
API v1.0 based response. true when successful, use REST-Get-Px-NtpServers to pull the current list.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER NtpArray
NtpArray Array / List of NTP Servers to remove.

.EXAMPLE
REST-Remove-Px-NtpServers `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $AuthHeader `
  -NtpArray $CurrentNtpServers
'17-Jul-21 14:34:20' | INFO  | Removing NTP Servers:
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp1xxx'
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp2xxx'
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp1xxx'
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp1xxx'
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp1xxx'

value
-----
True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object]  $NtpArray
  )

  write-log -message "Removing NTP Servers:"

  foreach ($NTP in $NtpArray){
    write-log -message "NTP: '$NTP'"
  }
  if ($NtpArray.count -eq 1){
    $JsonPayload = "[`"$NtpArray`"]"
  } else {
    $JsonPayload = $NtpArray
  }
  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/ntp_servers/remove_list"
    Method      = "POST"
    Body        = $JsonPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add Px Ntp Servers 
##################################################################

Function REST-Add-Px-NtpServers {
<#
.SYNOPSIS
Adds the array list of specified NTP servers, works with PE and PC

.DESCRIPTION
API v1.0 based response. true when successful, use REST-Get-Px-NtpServers to pull the current list.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER NtpArray
NtpArray Array / List of NTP Servers to Add.

.EXAMPLE
PS C:\Program Files\PowerShell\7> REST-Add-Px-NtpServers `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $AuthHeader `
  -NtpArray $CurrentNtpServers
'17-Jul-21 14:34:20' | INFO  | Adding NTP Servers:
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp1xxx'
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp2xxx'
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp1xxx'
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp1xxx'
'17-Jul-21 14:34:20' | INFO  | NTP: 'ntp1xxx'

value
-----
True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object]  $NtpArray
  )

  write-log -message "Adding NTP Servers:"

  foreach ($NTP in $NtpArray){

    write-log -message "NTP: '$NTP'"

  }

  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/ntp_servers/add_list"
    Method      = "POST"
    Body        = $NtpArray | convertto-json -Depth 2 -AsArray
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add Px Dns Servers 
##################################################################

Function REST-Add-Px-DnsServers {
<#
.SYNOPSIS
Adds the array list of specified DNS servers, works with PE and PC

.DESCRIPTION
API v1.0 based response. Array of DNS servers

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER DnsArray
DnsArray Array / List of DNS Servers to Add.

.EXAMPLE
REST-Add-Px-DnsServers `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $AuthHeader `
  -DnsArray $CurrentDnsServers
'17-Jul-21 14:34:20' | INFO  | Adding Dns Servers:
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns1xxx'
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns2xxx'
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns1xxx'
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns1xxx'
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns1xxx'

value
-----
True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $DnsArray
  )

  write-log -message "Adding Dns Servers:"

  foreach ($Dns in $DnsArray){

    write-log -message "Dns: '$Dns'"

  }

  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/name_servers/add_list"
    Method      = "POST"
    Body        = $DnsArray | convertto-json -Depth 2 -AsArray
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Remove Px Dns Servers 
##################################################################

Function REST-Remove-Px-DnsServers {
<#
.SYNOPSIS
Removes the array list of specified DNS servers, works with PE and PC

.DESCRIPTION
API v1.0 based response. Array of DNS servers as input, use REST-Get-Px-DnsServers to pull that list.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER DnsArray
DnsArray Array / List of DNS Servers to Remove.

.EXAMPLE
REST-Remove-Px-DnsServers `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $AuthHeader `
  -DnsArray $CurrentDnsServers
'17-Jul-21 14:34:20' | INFO  | Removing Dns Servers:
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns1xxx'
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns2xxx'
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns1xxx'
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns1xxx'
'17-Jul-21 14:34:20' | INFO  | Dns: 'Dns1xxx'

value
-----
True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $DnsArray
  )

  write-log -message "Removing Dns Servers:"

  foreach ($Dns in $DnsArray){
    write-log -message "Dns: '$Dns'"
  }


  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/name_servers/remove_list"
    Method      = "POST"
    Body        = $DnsArray | convertto-json -asarray
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Px Dns Servers 
##################################################################

Function REST-Get-Px-DnsServers {
<#
.SYNOPSIS
Retrieves the list of current DNS servers, works with PE and PC

.DESCRIPTION
API v1.0 based response. Array of DNS servers

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.EXAMPLE
REST-Get-Px-DnsServers `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $AuthHeader
'17-Jul-21 14:14:43' | INFO  | Retrieving DNS Servers
ntp1-xxxxx
ntp2-xxxxx
ntp1-xxxxx
ntp1-xxxxx
ntp1-xxxxx
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Retrieving DNS Servers"

  $RequestPayload = @{
    Uri         = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/name_servers"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName) `
    -LastError $false `
    -Retry 0
} 

##################################################################
# Get Multi Cluster Status
##################################################################

Function REST-Get-Pe-MultiCluster {
<#
.SYNOPSIS
Gets the PC Join status for Prism Element

.DESCRIPTION
API v1.0 based response. State of PC mapping.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.EXAMPLE
REST-Get-Pe-MultiCluster `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'17-Jul-21 18:54:03' | INFO  | Retrieving Multi Cluster State

clusterUuid            : c9fb9229-5e4c-4e31-836f-2835980892f4
clusterDetails         : @{clusterName=xxxxx; ipAddresses=System.Object[]; clusterAddresses=System.Object[];
                         clusterFullyQualifiedDomainName=xxxxxx; multicluster=True; username=;
                         password=; prcCluster=False; reachable=True; port=}
configDetails          :
filters                : {}
clusterTimestampUsecs  : 0
nosVersion             :
nosFullVersion         :
markedForRemoval       : False
remoteConnectionExists : True
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Retrieving Multi Cluster State"

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/multicluster/cluster_external_state"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add Multi Cluster
##################################################################

Function REST-Add-Pe-MultiCluster {
<#
.SYNOPSIS
Joins Prism Element towards Prism Central

.DESCRIPTION
API v1.0 based response. Main function to join a prism element towards a prism Central instance.
The command is targeted towards Prism Element, which communicates with Prism Central and requests the join.
Follow the join tasks to see the result of the command.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element instance.

.PARAMETER PcClusterIp
PcClusterIp Target PC to join.

.PARAMETER PcClusterUser
PcClusterUser username for target PC, needs to be an API Admin account.

.PARAMETER PcClusterPass
PcClusterPass password for target PC

.EXAMPLE


#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [string] $PcClusterUser,
    [parameter(mandatory)] [string] $PcClusterPass
  )

  write-log -message "Adding Multi Cluster State"

  $JsonPayload = @"
{
    "ipAddresses": ["$($PcClusterIp)"],
    "username": "$($PcClusterUser)",
    "password": "$($PcClusterPass)",
    "port": 9440
}
"@

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/multicluster/prism_central/register"
    Method      = "POST"
    Body        = $JsonPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Pe networks
##################################################################

Function REST-Get-Pe-Networks {
<#
.SYNOPSIS
Gets Prism Element Networks

.DESCRIPTION
API v2.0 based response. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element Cluster.

.EXAMPLE
REST-Get-PE-Networks `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'17-Jul-21 19:10:52' | INFO  | Query PE Networks

metadata                                    entities
--------                                    --------
@{grand_total_entities=8; total_entities=8} {@{logical_timestamp=7; vlan_id=115; ip_config=; uuid=d9ef5d91-1499-4aab-9…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Query PE Networks"

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v2.0/networks"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Prx networks
##################################################################

Function REST-Get-Prx-Networks {
<#
.SYNOPSIS
Gets Prism Element Networks using PC Proxy

.DESCRIPTION
API v2.0 based response. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element Cluster.

.PARAMETER ClusterUUID
ClusterUUID the target cluster UUID.

.EXAMPLE
REST-Get-Prx-Networks `
       -PEClusterIp $MainVars.Cluster.PeClusterIp `
       -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
       -ClusterUUID xxxx
'17-Jul-21 19:10:52' | INFO  | Query PE Networks

metadata                                    entities
--------                                    --------
@{grand_total_entities=8; total_entities=8} {@{logical_timestamp=7; vlan_id=115; ip_config=; uuid=d9ef5d91-1499-4aab-9…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUUID
  )

  write-log -message "Query Pe Networks through PC"

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v2.0/networks?proxyClusterUuid=$($ClusterUUID)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Prx Containers
##################################################################

Function REST-Prx-Get-Containers {
<#
.SYNOPSIS
Gets Prism Element Containers using PC Proxy

.DESCRIPTION
API v2.0 based response. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ClusterUUID
ClusterUUID the target cluster UUID.

.EXAMPLE
REST-PRX-Get-Containers `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ClusterUUID 0005ba33-a0b7-8458-0548-48df37c60a60
'17-Jul-21 20:49:09' | INFO  | Executing Container List

metadata                                                                                                            ent
                                                                                                                    iti
                                                                                                                    es
--------                                                                                                            ---
@{grandTotalEntities=3; totalEntities=3; filterCriteria=; sortCriteria=; page=1; count=3; startIndex=1; endIndex=3} {@…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUUID
  )

  Write-Log -message "Executing Container List"

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/containers?proxyClusterUuid=$($ClusterUUID)"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Pe Containers
##################################################################

Function REST-Get-Pe-Containers {
<#
.SYNOPSIS
Gets Prism Element Containers

.DESCRIPTION
API v2.0 based response. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element Cluster.

.EXAMPLE
REST-Get-Pe-Containers `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'17-Jul-21 20:52:07' | INFO  | Executing Container List

metadata                                                                                                            ent
                                                                                                                    iti
                                                                                                                    es
--------                                                                                                            ---
@{grandTotalEntities=3; totalEntities=3; filterCriteria=; sortCriteria=; page=1; count=3; startIndex=1; endIndex=3} {@…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  Write-Log -message "Executing Container List"

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/containers"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Delete Pe Container
##################################################################

Function REST-Delete-Pe-Container {
<#
.SYNOPSIS
Deletes Prism Element Containers

.DESCRIPTION
API v2.0 based response. Deletes prism Element container if the condition allows that.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ContainerUuid
Container Uuid for the target container to delete.

.EXAMPLE
REST-Delete-Pe-Containers `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -containerUuid xyz
'17-Jul-21 20:52:07' | INFO  | Deleting Container 'xyz'
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ContainerUuid
  )

  Write-Log -message "Deleting Container '$($ContainerUuid)'"

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/containers/$($containerUuid)"
    Method      = "Delete"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Delete Pe Container
##################################################################

Function REST-Get-Pe-Container-VDisks {
<#
.SYNOPSIS
Gets Prism Element Container VDisks

.DESCRIPTION
API v2.0 based response. Entities and metadata are included. All VDisks in this container will be returned.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ContainerUuid
Container Uuid of the container to retrieve.

.EXAMPLE
REST-Get-Pe-Container-VDisks `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -ContainerUuid $default.containerUuid
'17-Jul-21 22:01:10' | INFO  | Retrieving Container '' VDisks

metadata                                             entities
--------                                             --------
@{grand_total_entities=4; total_entities=0; count=4} {@{name=0005ba33-a0b7-8458-0548-48df37c60a60::NFS:2:0:457; cluste…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ContainerUuid
  )

  Write-Log -message "Retrieving Container '$($ContainerUuid)' VDisks"

  $RequestPayload = @{
    Uri         = "https://$($PeClusterIp):9440/api/nutanix/v2.0/storage_containers/$ContainerUuid/vdisks"
    Method      = "Get"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Set Pe Container
##################################################################

Function REST-Set-Pe-Container {
<#
.SYNOPSIS
Updates Container Spec, requires a single entity from REST-Get-Pe-Containers as input

.DESCRIPTION
Requires the full container object to be sent inside. See ContainerObj Parameter.
Any property can be updated using this method, Get Detailed object, modify in process.
Send the object back using this command.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ContainerObj
ContainerObj a single entity from REST-Get-Pe-Containers, object

.EXAMPLE
REST-Set-Pe-Container `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -ContainerObj $default
  '17-Jul-21 22:06:04' | INFO  | Executing Container Payload Update

value
-----
 True

#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $ContainerObj
  )

  Write-Log -message "Executing Container Payload Update"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/containers/"
    Method               = "PUT"
    Body                 = $ContainerObj
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Set Pe Hosts
##################################################################

Function REST-Get-Pe-Hosts {
<#
.SYNOPSIS
Gets the hostlist from Prism Element.

.DESCRIPTION
Metadata and Entities based response V1 API Call.
Pulls all the Prism Element hosts. Pagination not supported.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element Cluster.

.EXAMPLE
REST-Get-Pe-Hosts `
  -PEClusterIP $MainVars.Cluster.PEClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'17-Jul-21 22:11:11' | INFO  | Executing Get Hosts Query

metadata                                                                                                            ent
                                                                                                                    iti
                                                                                                                    es
--------                                                                                                            ---
@{grandTotalEntities=3; totalEntities=3; filterCriteria=; sortCriteria=; page=1; count=3; startIndex=1; endIndex=3} {@…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  Write-Log -message "Executing Get Hosts Query"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/hosts"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Delete Prx Remote Site
##################################################################

Function REST-Delete-Prx-Remote-Site {
<#
.SYNOPSIS
Deletes a PE Remote site through Prism Central Proxy URL

.DESCRIPTION
API v1.0 based response. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ClusterUuid 
Cluster UUID is the remote cluster UUID, used for PC Proxy Command

.PARAMETER RemoteSiteName
RemoteSiteName is the name of the remote site, best is to retrieve first, based on matchers, the delete name is case sensitive.

.EXAMPLE
REST-Delete-Prx-Remote-Site -PcClusterIp 10.x.x.x -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead -RemoteSiteName RS_RSE12851-NX0001 -ClusterUUID 0005aa62-797b-1f9a-6c01-48df37c63270
'18-Jul-21 09:37:00' | INFO  | Remote Site Delete 'RS_RSxx-Nxxx1' via PC Cluster '0005aa62-797b-1f9a-6c01-48df37c63270'

value
-----
True
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $RemoteSiteName,
    [parameter(mandatory)] [string] $ClusterUuid
  )

  write-log -message "Remote Site Delete '$($RemoteSiteName)' via PC Cluster '$($ClusterUuid)'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/remote_sites/$($RemoteSiteName)?proxyClusterUuid=$($ClusterUuid)"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Prx Hosts
##################################################################

Function REST-Get-Prx-Hosts {
<#
.SYNOPSIS
Retrieves the PE Hosts through Prism Central Proxy URL

.DESCRIPTION
Uses the API Proxy URL Construct to query the Prism Element Host V1 API Using the PC API Gateway.
This command is useful for remote clusters without local credential context.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ClusterUuid 
Cluster UUID is the remote cluster UUID, used for PC Proxy Command

.EXAMPLE
REST-Get-Prx-Hosts `
  -PcClusterIp x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -ClusterUuid 0005c7aa-d5c3-450a-7c31-d4f5ef2b1620
'22-Jul-21 21:23:55' | INFO  | Query PE Hosts through PC, using cluster: '0005c7aa-d5c3-450a-7c31-d4f5ef2b1620'

metadata                                                                                                            ent
                                                                                                                    iti
                                                                                                                    es
--------                                                                                                            ---
@{grandTotalEntities=3; totalEntities=3; filterCriteria=; sortCriteria=; page=1; count=3; startIndex=1; endIndex=3} {@…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid
  )

  write-log -message "Query PE Hosts through PC, using cluster: '$ClusterUuid'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/hosts?proxyClusterUuid=$($ClusterUuid)"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add Px Auth Config
##################################################################

Function REST-Add-Px-AuthConfig {
<#
.SYNOPSIS
Configures Authentication Directory in Prism Central or Element.

.DESCRIPTION
API v1.0 based response. 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthConfigName
AuthConfigName, the name of the directory object that is to be created.

.PARAMETER DomainName
DomainName FQDN or netbios domain name, will be converted to netbios.

.PARAMETER LdapUser
LDAP User, user thats used for LDAP binding, will be joined with netbios prefix, just send the username.

.PARAMETER LdapPass
LDAP Pass, password for LDAP binding.

.PARAMETER LdapFqdn  
LDAP FQDN, the fqdn of the domain controller or domain.

.PARAMETER LdapPort
LDAP Port, can be 3269 or 636, will auto switch between LDAPs or LDAP

.PARAMETER Recursive
Recursive, this is the group search mode, nutanix implementation is super slow, dont use recursive.

.EXAMPLE
REST-Add-Px-AuthConfig  `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $BasicHeader `
  -PxClusterPass $PxClusterPass `
  -domainname $MainVars.AutoDC.LdapDomain `
  -ldapuser $MainVars.creds.Password_Vault.LDAP.username `
  -ldappass $MainVars.creds.Password_Vault.LDAP.secret `
  -ldapFQDN $MainVars.AutoDC.LdapDomainHost `
  -ldapPort $MainVars.System.DomainControllerPort `
  -Recursive $MainVars.System.DomainGroupSearchMode
'23-Jul-21 14:23:38' | INFO  | Configuring AuthConfig with server 'xxx.com'

directoryType          : ACTIVE_DIRECTORY
connectionType         : LDAP
directoryUrl           : ldaps://xxx.com:636
domain                 : xxxx.com
name                   : xxxx
groupSearchType        : RECURSIVE
serviceAccountUsername : xxx\xxxxxx
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $DomainName,
    [parameter(mandatory)] [string] $AuthConfigName,
    [parameter(mandatory)] [string] $LdapUser,
    [parameter(mandatory)] [string] $LdapPass,
    [parameter(mandatory)] [string] $LdapFqdn,
    [parameter(mandatory)] [string] $LdapPort = 3268,
    [parameter(mandatory)] [string] $Recursive
  )

  $Netbios = $domainname.split(".")[0];
  
  if ($ldapport -eq "636" -or $ldapport -eq "3269"){
    $ldap = "ldaps"
  } else {
    $ldap = "ldap"
  }

  write-log -message "Configuring AuthConfig with server '$($ldapFQDN)'"

  $PsHashPayload = @{
    name = $Netbios
    domain = $DomainName
    directoryUrl = "$($ldap)://$($ldapFQDN):$($ldapPort)"
    groupSearchType = $Recursive
    directoryType = "ACTIVE_DIRECTORY"
    connectionType = "LDAP"
    serviceAccountUsername = "$($Netbios)\$($ldapUser)"
    serviceAccountPassword = $ldapPass
  }

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Remove Px Auth Config
##################################################################

Function REST-Remove-Px-AuthConfig {
<#
.SYNOPSIS
Removes Authentication Directory in Prism Central or Element.

.DESCRIPTION
Returns true if successful. 
Compatible with both PC and PE retrieves the Directory Configuration for that instance.
Prism versions in past life had issues with upper and lower case auth names.
For certainty make sure you use lower case names.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthConfigName
AuthConfigName, the name of the directory object that is to be created.

.EXAMPLE
REST-Remove-Px-AuthConfig `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $BasicHeader `
  -name $authdom.directoryList.name
'23-Jul-21 14:22:44' | INFO  | Removing AuthConfig xx

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $AuthConfigName
  )

  write-log -message "Removing AuthConfig '$AuthConfigName'"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories/$AuthConfigName"
    Method               = "Delete"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Px Auth Config
##################################################################

Function REST-Get-Px-AuthConfig {
<#
.SYNOPSIS
Retrieves Authentication Directory in Prism Central or Element.

.DESCRIPTION
Compatible with both PC and PE retrieves the Directory Configuration for that instance.
Prism versions in past life had issues with upper and lower case auth names.
For certainty make sure you use lower case names.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.EXAMPLE
REST-Get-Px-AuthConfig `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $BasicHeader
'23-Jul-21 15:29:31' | INFO  | Retrieving AuthConfig

authTypeList               directoryList
------------               -------------
{LOCAL, DIRECTORY_SERVICE} {@{directoryType=ACTIVE_DIRECTORY; connectionType=LDAP; directoryUrl=ldaps://xxx.com:636…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Retrieving AuthConfig"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig"
    Method               = "Get"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add Px Role Mapping
##################################################################

Function REST-Add-Px-RoleMapping {
<#
.SYNOPSIS
Creates a Role mapping in Prism Central or Element. Binding AD Groups / users to Cluster Roles.

.DESCRIPTION
API v1.0 based response. Only 1 object is supported in this module.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthConfigName
AuthConfigName, used for the directory mapping name (depends on add-px-authconfig)

.PARAMETER EntityName
EntityName Common name of the group or use to add, UPN or CN 

.PARAMETER Mode  
Mode, for PC CLUSTER(Admin), USER(Admin) or VIEWER, for PE, BACKUP is also a possible option 

.PARAMETER Type  
Type, GROUP or USER

.EXAMPLE
REST-Add-Px-RoleMapping `
   -PxClusterIp $PxClusterIp `
   -AuthHeader $BasicHeader `
   -domainname $MainVars.AutoDC.LdapDomain `
   -GroupName $PEAdmingroup `
   -Mode "USER"
 '23-Jul-21 14:50:38' | INFO  | Adding RoleMapptings
 
 directoryName role            entityType entityValues
 ------------- ----            ---------- ------------
 xxxx        ROLE_USER_ADMIN GROUP      {xxxxx}

 #>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $EntityName,
    [parameter(mandatory)] [string] $AuthConfigName,
    [parameter(mandatory)] [string] $Mode = "CLUSTER",
    [parameter(mandatory)] [string] $Type = "GROUP"
  )

  write-log -message "Adding RoleMapptings: '$Mode' with AuthConfig : '$AuthConfigName' using type: '$($Type)', Entity: ' $($EntityName)'" 

  if ($Mode -eq "VIEWER"){
    $Role = "ROLE_CLUSTER_VIEWER"
  } else {
    $Role = "ROLE_$($mode)_ADMIN"
  }

  $PsHashPayload =@{
    directoryName = $AuthConfigName
    role = $Role
    entityType = $Type 
    entityValues = @($EntityName)
  }

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories/$AuthConfigName/role_mappings"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Px Role Mapping
##################################################################

Function REST-Get-Px-RoleMapping {
<#
.SYNOPSIS
Gets a Role mapping in Prism Central or Element. Binding AD Groups / users to Cluster Roles.

.DESCRIPTION
API v1.0 based response. 1 Single mapping can contain multiple groups or users, but only 1 mapping of each type can exist.
USER / GROUP 

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthConfigName
AuthConfigName, used for the directory mapping name (depends on add-px-authconfig)

.EXAMPLE
REST-Get-Px-RoleMapping `
  -PxClusterIp $PxClusterIp `
  -AuthHeader $BasicHeader `
  -domainname $MainVars.AutoDC.LdapDomain `
  -AuthConfigName $AuthConfigName
'23-Jul-21 14:50:38' | INFO  | Retrieving RoleMapptings

directoryName role            entityType entityValues
------------- ----            ---------- ------------
xxxx        ROLE_USER_ADMIN GROUP      {xxxxx} 
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $AuthConfigName
  )

  write-log -message "Retrieving RoleMappings"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories/$AuthConfigName/role_mappings"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Delete Px Role Mapping
##################################################################

Function REST-Delete-Px-RoleMapping {
<#
.SYNOPSIS
Gets a Role mapping in Prism Central or Element. Binding AD Groups / users to Cluster Roles.

.DESCRIPTION
API v1.0 based response.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthConfigName
AuthConfigName, used for the directory mapping name (depends on add-px-authconfig)

.PARAMETER Mode
Mode, for PC CLUSTER, VIEWER or USER, for PE, BACKUP is also a possible option. Case sensitive

.PARAMETER Type
Type, Group or User

.EXAMPLE
REST-Delete-Px-RoleMapping `
  -PxClusterIP 10.10.0.30 `
  -AuthHeader $BasicHead `
  -AuthConfigName MMouse `
  -mode CLUSTER -Type user

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $AuthConfigName,
    [parameter(mandatory)] [string] $mode = "CLUSTER",
    [parameter(mandatory)] [string] $Type
  )
  if ($Mode -eq "VIEWER"){
    $Role = "ROLE_CLUSTER_VIEWER"
  } else {
    $Role = "ROLE_$($mode)_ADMIN"
  }

  write-log -message "Deleting RoleMapping: '$Role' with type: '$type'"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/authconfig/directories/$AuthConfigName/role_mappings?&entityType=$type&role=$Role"
    Method               = "Delete"
    Headers              = $AuthHeader

  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get AD Service in Prism Central
##################################################################

Function REST-Query-Pc-Directory-Services {
<#
.SYNOPSIS
Retrieves all auth services in object form, this so the auth provider can be queried at a given time.

.DESCRIPTION
API v3.1 based response. 

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Query-Pc-Directory-Services `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'26-Jul-21 20:15:55' | INFO  | Query for AD Connections.

api_version metadata                                   entities
----------- --------                                   --------
3.1         @{total_matches=1; kind=directory_service} {@{status=; spec=; metadata=}}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Query AD Connections."

  $PsHashPayload = @{
    kind   = "directory_service"
    length = 100
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/directory_services/list"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Get AD Service in Prism Central
##################################################################

Function REST-Query-Pc-Directory-Objects {
<#
.SYNOPSIS
Searches AD Through the configured auth provider in Prism Central

.DESCRIPTION
This API Call is known to timeout on large active directory systems.
This is a known limitation of the Nutanix LDAP Search implementation.
Disable wildcard searches to improve performance.
The invoke-rest handler has built in retry to handle these timeouts.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER WildCard  
WildCard enables or disables wildcard searches.
This improves timeouts. Disable wildcards on preference.
Although enabled by default. 

.PARAMETER SearchString
SearchString object name to look for.

.PARAMETER AuthUuid
AuthUuid, retrieved from REST-Query-Pc-Directory-Services

.EXAMPLE
PS C:\Program Files\PowerShell\7> REST-Query-Pc-Directory-Objects `
>>       -PcClusterIp $MainVars.AutoDC.PcClusterIp `
>>       -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
>>       -AuthUuid $DirSvc.metadata.uuid `
>>       -SearchString $GroupSearchValue `
>>       -WildCard $true
'26-Jul-21 20:27:47' | INFO  | Query for AD Objects, using auth provider 'eff5c133-c3a7-4286-823e-3b1d2b9e799d'

search_result_list domain_name api_version metadata
------------------ ----------- ----------- --------
{}                 xxxx 3.1         @{query=NTxadmin; searched_attribute_list=System.Object[]; returned_attribute_list=System.Object[]; is_wildcard_search=True}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
                           [bool]   $WildCard = $true,
    [parameter(mandatory)] [string] $SearchString,
    [parameter(mandatory)] [string] $AuthUuid
  )

  write-log -message "Query for AD Objects, using auth provider '$AuthUuid'"

  $PsHashPayload = @{
    query                   = $SearchString
    returned_attribute_list = $(
      "memberOf"
      "member"
      "userPrincipalName"
      "distinguishedName"
    )
    searched_attribute_list = @(
      "name"
      "userPrincipalName"
      "distinguishedName"
    )
    is_wildcard_search = $WildCard
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/directory_services/$($AuthUuid)/search"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Enable Calm in PC
##################################################################

Function REST-Enable-Pc-Calm {
<#
.SYNOPSIS
Enables the Calm app in PC

.DESCRIPTION
Calm is the automation engine inside Nutanix Prism Central.
Requires the data services IP to be set on the PE Cluster, adds a few GB to the PC RAM allocation.
Calm is based out of 2 containers, they take some time to start.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Enable-Pc-Calm `
  -PcClusterIp 10.10.0.32 `
  -AuthHeader $BasicHead

task_uuid
---------
ef4e1eb5-430d-4bc2-98b3-7bb2cc13f4b0
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Enabling Calm"

  $PsHashPayload = @{
    state               = "ENABLE"
    enable_nutanix_apps = $true
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/services/nucalm"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Enable Flow in PC
##################################################################

Function REST-Enable-Pc-Flow {
<#
.SYNOPSIS
Enables the Flow app in PC

.DESCRIPTION
Flow is the virtual networking service from Nutanix. Do not enable if not needed.
Flow is undergoing heavy development. Its not recommended to enable if not used.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Enable-Pc-Flow `
  -PcClusterIp 10.10.0.32 `
  -AuthHeader $BasicHead

task_uuid
---------
ef4e1eb5-430d-4bc2-98b3-7bb2cc13f4b0
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Enabling Flow"

  $PsHashPayload = @{
    state               = "ENABLE"
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/services/microseg"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Flow Status in PC
##################################################################

Function REST-Get-Pc-Flow-Status {
<#
.SYNOPSIS
Checks if flow is enabled in PC

.DESCRIPTION
Just a status checker if flow is enabled.
Returns ENABLED or DISABLED in the service_enablement_status object.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pc-Flow-Status `
  -PcClusterIp x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Admin.BasicHead
'27-Jul-21 20:48:21' | INFO  | Getting Flow Enabled Status

service_enablement_status
-------------------------
DISABLED

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Getting Flow Enabled Status"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/services/microseg/status"
    Method               = "Get"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Enable Foundation Central in PC
##################################################################

Function REST-Enable-Pc-FoundationCentral {
<#
.SYNOPSIS
Enables the Foundation Central  app in PC

.DESCRIPTION
Enables foundation central app in PC, adds a few GB to the PC RAM allocation
Uses Genesis nested JSON Structure, Escaped JSON in a JSON.....

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Enable-Pc-FoundationCentral `
  -PcClusterIp 10.10.0.32 `
  -AuthHeader $BasicHead

value
-----
{".return": [true, null]}

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Enabling Foundation Central"

  $PsHashPayload1 = @{
    ".oid" = "ClusterManager"
    ".method" = "enable_service"
    ".kwargs" = @{
      service_list_json = @{ service_list = @("FoundationCentralService")} | convertto-json
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Foundation Central Status in PC
##################################################################

Function REST-Get-Pc-FoundationCentral-Status {
<#
.SYNOPSIS
Gets the Foundation Central Status in PC

.DESCRIPTION
Uses Genesis nested JSON Structure, Escaped JSON in a JSON.....
Pulls the status for foundation central.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pc-FoundationCentral-Status `
  -PcClusterIp x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Admin.BasicHead
'27-Jul-21 20:56:27' | INFO  | Getting Foundation Central Status

value
-----
{".return": [true, ""]}

PS C:\Program Files\PowerShell\7>
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Getting Foundation Central Status"

  $PsHashPayload1 = @{
    ".oid" = "ClusterManager"
    ".method" = "is_service_enabled"
    ".kwargs" = @{
      service_name = "FoundationCentralService"
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Get Prism EULA Registration Status
##################################################################

Function REST-Get-Px-EULA-Status {
<#
.SYNOPSIS
Retrieves the Prism Central or Element EULA Values. 

.DESCRIPTION
This is used to determine if the EULA is already entered.
Warning the customer should always have accepted the EULA or understand it being auto accepted.
entities.userdetailslist in the output contains the existing registration.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" } 

.EXAMPLE
REST-Get-Px-EULA-Status `
  -PxClusterIP x.x.x.x -AuthHeader `
  $MainVars.Creds.Password_Vault.Central_Pc_Admin.BasicHead
'27-Jul-21 21:01:38' | INFO  | Getting EULA Status

metadata                                 entities
--------                                 --------
@{grandTotalEntities=1; totalEntities=0} {@{uuid=261e68aa-5835-4fd9-b396-40e77afdd8ed; content=&lt;div id=&quot;eula&q…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Getting EULA Status"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/eulas"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Set Prism EULA Registration
##################################################################

Function REST-Set-Px-EULA {
<#
.SYNOPSIS
Sets the Prism Central or Element EULA Values. 

.DESCRIPTION
Warning the customer should always have accepted the EULA or understand it being auto accepted.
entities.userdetailslist in the output contains the existing registration.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER EulaName
The user name used to accept the EULA

.PARAMETER EulaCompany
The Company used to accept the EULA

.PARAMETER EulaRole
The Job Role of the user used to accept the EULA

.EXAMPLE
REST-Get-Px-EULA-Status `
  -PxClusterIP x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Admin.BasicHead
'27-Jul-21 21:01:38' | INFO  | Getting EULA Status

metadata                                 entities
--------                                 --------
@{grandTotalEntities=1; totalEntities=0} {@{uuid=261e68aa-5835-4fd9-b396-40e77afdd8ed; content=&lt;div id=&quot;eula&q…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $EulaName,
    [parameter(mandatory)] [string] $EulaCompany,
    [parameter(mandatory)] [string] $EulaRole
  )

  $PsHashPayload= @{
    username     ="$($EulaName)"
    companyName  ="$($EulaCompany)"
    jobTitle     ="$($EulaRole)"
  } 

  write-log -message "Accepting EULA on behalf: '$($EulaName)'"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/eulas/accept"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Set Prism Pulse Mode
##################################################################

Function REST-Set-Px-Pulse {
<#
.SYNOPSIS
Sets the Prism Central or Element Pulse Values. 

.DESCRIPTION
Can be used to enable or disable pulse, input should be string.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER State
State true or false, lowercase

.EXAMPLE
REST-Set-Px-Pulse `
  -PxClusterIP xxx `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -State "true"
'09-Aug-21 20:59:11' | INFO  | Setting Pulse Status towards: 'true'

enable                           : True
nosVersion                       :
isPulsePromptNeeded              : False
remindLater                      : False
enableDefaultNutanixEmail        : False
defaultNutanixEmail              : nos-asups@nutanix.com
emailContactList                 : {}
verbosityType                    : BASIC_COREDUMP
smtpServer                       : @{address=smtp-gw.xxx.com; serverAddress=; port=25; username=; password=;
                                   secureMode=NONE; fromEmailAddress=xxx-NX0000@xxx.xxx.com; emailStatus=}
identificationInfoScrubbingLevel : AUTO
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $State
  )

  $State = $state.tolower() 

  $PsHashPayload= @{
    enable                    = $State
    enableDefaultNutanixEmail = "false"
    isPulsePromptNeeded       = "false"
  } 

  write-log -message "Setting Pulse Status towards: '$($State)'"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/pulse"
    Method               = "PUT"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Run Px LCM Inventory
##################################################################

Function REST-Run-Px-LCM-Inventory {
<#
.SYNOPSIS
Executes the LCM inventory command.

.DESCRIPTION
Uses legacy genesis call. Both Prism Central and Prism Element are supported.
Returns a traceable task id. Use the task ID to monitor the progress.

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Run-Px-LCM-Inventory `
  -PxClusterIP $MainVars.cluster.PEClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'02-Aug-21 07:11:30' | INFO  | Starting Inventory on: 'x.x.x.x'

value
-----
{".return": "68e9d835-1467-4a5d-999c-f2f85d2b5613"}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload1 = @{
    ".oid" = "LifeCycleManager"
    ".method" = "lcm_framework_rpc"
    ".kwargs" = @{
      method_class = "LcmFramework"
      method = "perform_inventory"
      args = @(
        "http://download.nutanix.com/lcm/2.0"
      )
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  write-log -message "Starting Inventory on: '$($PxClusterIP)'"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2 
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Px LCM Details
##################################################################

Function REST-Get-Px-LCM-Details {
<#
.SYNOPSIS
Retrieves the current LCM Details, proxy URL, version etc.

.DESCRIPTION
Uses legacy genesis call. Both Prism Central and Prism Element are supported.

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-LCM-Details `
  -PxClusterIP xxx `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead
'09-Aug-21 21:23:38' | INFO  | Starting Inventory on: 'xxx7'

is_darksite                  : True
ui_version                   : 2.4.2.813
recovery_disabled            : False
user_preferences             : @{user_http_changed=True}
enable_rim_verification      : True
uploaded_bundle              : False
lcm_pc_enabled               : False
version                      : 2.4.2.25804
auto_update_enabled          : False
semantic_version             : 2.4.2
lcm_cpdb_table_def_list      : @{available_version=lcm_available_version_v2; metric_operation=lcm_metric_operation_v1;
                               product_meta_entity=lcm_product_meta_entity_v2; image=lcm_image_v1;
                               metric_action=lcm_metric_action_v1; bundle=lcm_bundle_v1; entity=lcm_entity_v2;
                               module=lcm_module_v2; deployable_version=lcm_deployable_version_v1;
                               metric_entity=lcm_metric_entity_v1}
distribute_inventory         : True
lcm_standalone_ui_enabled    : True
metrics_enabled              : True
enable_pm_verification       : True
next_update                  : 03:00
build_type                   : connected_site
parallel_limit               : 32
product_meta_url             : http://xxx/release
url                          : http://xxx/release
api_enabled                  : True
enable_https                 : False
auto_inventory_enabled       : True
v4_api_enabled_default       : True
deprecated_software_entities : {Firmware}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload1 = @{
    ".oid" = "LifeCycleManager"
    ".method" = "lcm_framework_rpc"
    ".kwargs" = @{
      method_class = "LcmFramework"
      method = "get_config"
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  write-log -message "Pulling LCM Details from: '$($PxClusterIP)'"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2 
  }

  return ((Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)).value | convertfrom-json -ea:0).".return"
} 

##################################################################
# Get All Categories
##################################################################

Function REST-Get-Pc-Categories {
<#
.SYNOPSIS
Retrieves all the categories from Pc, converts the output. 

.DESCRIPTION
Uses Pc Group call, this is PC only. Output is not human readable, this function converts the output also.

.PARAMETER PxClusterIp
PxCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pc-Categories `
  -PcClusterIp x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead
'10-Aug-21 18:22:54' | INFO  | Getting All Categories using Prism Group Call
'10-Aug-21 18:22:55' | INFO  | Converting to Readable Output.

CategoryName             Values
------------             ------
Active_Cluster_Workloads {VMs}
ADGroup                  {$Default}
AnalyticsExclusions      {AnomalyDetection, EfficiencyMeasurement}
App_Role                 {Application Server, BU5 TS Server, CCTV, Cluster Node…}
App_Type                 {0, 1, 2, 4…}
AppFamily                {Backup, BI-Productivity, Containers, Databases…}
AppName                  {FSOL 1, LIP App 1, LIP App 2, MHS PG DB…}
AppTier                  {Default}
AppType                  {Apache_Spark, Default, Employee_Payroll, Exchange…}
BU_Code                  {123, 124, 12851}
BU_Country               {SE}
BU_Type                  {R, RET}
CalmApplication          {123123213, Applicance Nutanix Move DSSE998-NX0000, Applicance Nutanix Move xxxxx, Applicance Nutanix Move xxxxx…}
CalmDeployment           {24aab91d_deployment, 3f263fde_deployment, 8ebcff15_deployment, b67c8583_deployment}
CalmPackage              {AHV_ICC_Package, AHV_LX_Package, Package1}
CalmPolicyEngineVM       {True}
CalmService              {Control Panel, Control_Panel, NEW_ICC_VM, NEW_LX_VM…}
CalmUsername             {1-click-nutanix, xxxx}
CityName                 {Almhult}
Country                  {SE}
Environment              {Dev, Production, Staging, Testing}
NW_NTXLAN_Name           {xxxxServers, xxxxx-103-Protected_Servers, xxxx-Protected_Servers-FW, xxxx-Servers…}
NW_VLAN_ID               {103, 104, 105, 135…}
OSType                   {Linux, Windows}
ProfileId                {0, 1, 11, 2…}
Quarantine               {Default, Forensics}
Region                   {EMEA}
Remote_Recovery_Site     {xxx-NX0000, DSSE999-NX0000, xxxxx, xxxx…}
SiteCode                 {xxx, xxxx, xxx}
Snap_Consistency         {CCG}
Snap_Repl_Policy         {GOLD, SILVER}
Sync_rep                 {Sync_rep}
TemplateType             {Application, Vm}
Timezone                 {UTC+00, UTC+02, UTC+09}
VirtualNetworkType       {Tenant, Test}
LdapDomain               {xxxx.com}

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload = @{
    entity_type = "category"
    query_name = "$($(new-guid).guid)"
    grouping_attribute = "abac_category_key"
    group_sort_attribute = "name"
    group_sort_order = "ASCENDING"
    group_count = 99999
    group_offset = 0
    group_attributes = $(@{
      attribute = "name"
      ancestor_entity_type = "abac_category_key"
    }
    @{
      attribute = "immutable"
      ancestor_entity_type = "abac_category_key"
    }
    @{
      attribute = "cardinality"
      ancestor_entity_type = "abac_category_key"
    }
    @{
      attribute = "description"
      ancestor_entity_type = "abac_category_key"
    }
    @{
      attribute = "total_policy_counts"
      ancestor_entity_type = "abac_category_key"
    }
    @{
      attribute = "total_entity_counts"
      ancestor_entity_type = "abac_category_key"
    }
    )
    group_member_count = 999999
    group_member_offset = 0
    group_member_sort_attribute = "value"
    group_member_sort_order = "ASCENDING"
    group_member_attributes = $(@{
      attribute = "name"
    }
    @{
      attribute = "value"

    })
  }

  write-log -message "Getting All Categories using Prism Group Call"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/groups"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  $GroupCall = Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

  Write-Log -message "Converting to Readable Output."

  $CatArr = $null
  Foreach ($item in $GroupCall.group_results){
    $Values = $null
    $Name = $item.group_summaries."sum:name".values.Values
    $item.entity_results | Foreach-Object {
      [array] $Values += $_.data.values.values
    }
    $CatObj = @{
      CategoryName = $Name
      Values  = $Values
    }
    [array] $CatArr += $CatObj
  }
  Return $CatArr
} 

##################################################################
# Import PC Images
##################################################################

Function REST-Import-Pc-Images {
<#
.SYNOPSIS
Imports images into PC, using source Cluster UUID

.DESCRIPTION
Imports all images based on a source cluster, requires the source cluster UUID as input.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
ClusterUuid cluster UUID to retrieve the images from.

.EXAMPLE
REST-Import-Pc-Images `
  -PcClusterIp x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -ClusterUuid 0005c933-ce1c-c52f-28fb-3cecef178131
'10-Aug-21 19:44:24' | INFO  | Importing Images, using source: '0005c933-ce1c-c52f-28fb-3cecef178131'

task_uuid
---------
a2889e5f-efe1-4585-9109-9b4381b62a46
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid    
  )

  write-log -message "Importing Images, using source: '$ClusterUuid'" 

  $PsHashPayload =@{
    image_reference_list = @()
    cluster_reference = @{
      uuid = $ClusterUuid
      kind = "cluster"
      name = "string"
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/images/migrate" 
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Delete VM Via PC
##################################################################

Function REST-Delete-Pc-Vm {
<#
.SYNOPSIS
Sends a Batch Delete job to the underlying Pe Cluster to delete the VM

.DESCRIPTION
Requires the cluster Uuid and Vm Uuid to be sent in.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER VmClusterUuid
Cluster UUID to delete the VM from.

.PARAMETER VmUuid
VmUuid is the uuid of the VM to delete

.EXAMPLE
REST-Delete-Pc-Vm `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -VmClusterUuid $Vm.spec.cluster_reference.uuid `
  -VmUuid $Vm.metadata.uuid
'14-Aug-21 12:06:54' | INFO  | Deleting VM '851affc8-1688-43e9-a9ce-49fa703357b6' run on cluster '0005c965-1e70-f02d-4808-d4f5ef2b0ea0'

taskUuid
--------
0a0c8562-c487-4691-86da-106cad8b57ce
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmClusterUuid,
    [parameter(mandatory)] [string] $VmUuid  
  )

  write-log -message "Deleting VM '$vmuuid' run on cluster '$VmClusterUuid'"

  $PsHashPayload = @{
    generic_dto = @{
      uuid = $VmUuid
    }
    cluster_uuid = $VmClusterUuid
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v0.8/vms/delete/fanout"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload | convertto-json -Depth 2 -AsArray
  }

  Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# List Cluster Object PC Proxy
##################################################################

Function REST-List-Prx-Cluster-Object {
<#
.SYNOPSIS
Sends GET Command to the Pe Cluster object using prism central proxy.

.DESCRIPTION
Requires the cluster Uuid, retrieved with PC cluster list command. 
Uses the Prism Central API Gateway Proxy construct.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Cluster UUID to query

.EXAMPLE
REST-List-Prx-Cluster-Object `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ClusterUuid $MyCluster.metadata.uuid
'19-Aug-21 21:26:14' | INFO  | Listing Cluster: '0005b697-34ec-366c-7861-48df37e17800' using PC Proxy.

metadata                                                                                                            en
                                                                                                                    ti
                                                                                                                    ti
                                                                                                                    es
--------                                                                                                            --
@{grandTotalEntities=1; totalEntities=1; filterCriteria=; sortCriteria=; page=1; count=1; startIndex=1; endIndex=1} {…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [String] $ClusterUuid
  )

  write-log -message "Listing Cluster: '$ClusterUuid' using PC Proxy."

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/clusters?proxyClusterUuid=$($ClusterUuid)"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Update Cluster Object PC Proxy
##################################################################

Function REST-Update-Prx-Cluster-Object {
<#
.SYNOPSIS
Sends a PUT Command to the Pe Cluster object using prism central proxy.

.DESCRIPTION
Requires the cluster object, retrieved with REST-List-Prx-Cluster-Object.
Uses the Prism Central API Gateway Proxy construct.

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterObj
Cluster Object, use REST-List-Prx-Cluster-Object as input

.EXAMPLE
PS C:\Program Files\PowerShell\7>  REST-Update-Prx-Cluster-Object `
>>           -PcClusterIp $MainVars.AutoDC.PcClusterIp `
>>           -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
>>           -ClusterObj $ClusterObj.entities[0]
'19-Aug-21 21:28:18' | INFO  | Updating Cluster Using PC Proxy '0005b697-34ec-366c-7861-48df37e17800'

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $ClusterObj
  )

  write-log -message "Updating Cluster Using PC Proxy '$($ClusterObj.uuid)'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/cluster?proxyClusterUuid=$($ClusterObj.uuid)"
    Method               = "PUT"
    Headers              = $AuthHeader
    Body                 = $ClusterObj
  }

  Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


##################################################################
# Get Pe Protection Domain Events
##################################################################

Function REST-Get-Pe-ProtectionDomain-Events {
<#
.SYNOPSIS
Gets the list of PD Events for a given PD, PDs force retrieval by name. Name must exist.

.DESCRIPTION
Gets the list of events from a PD.

.PARAMETER PeClusterIp
PeCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
Name of the protection domain

.EXAMPLE
REST-Get-Pe-ProtectionDomain-Events `
  -PeClusterIp 10.10.0.30 `
  -AuthHeader $BasicHead `
  -PdName HomeSnaps

metadata                                                                                  entities
--------                                                                                  --------
@{grandTotalEntities=19; totalEntities=14; page=1; count=1000; startIndex=1; endIndex=14} {@{id=7420274a-d073-4b83-a7db-c1c79e3df994; alertTypeUuid=SnapshotReadyAudit; checkI…

#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName
  )

  write-log -message "Pulling Events PD Name: '$($PdName)'"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)/events"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Pc Roles
##################################################################

Function REST-Get-Pc-Roles {
<#
.SYNOPSIS
Gets the list of PD Events for a given PD, PDs force retrieval by name. Name must exist.

.DESCRIPTION
Gets the roles from Prism Central, Roles are used for RBAC in Prism Central.
Prism Element does not have context of these roles.
There are 7-9 built in roles, and custom roles can also be created.
Roles themselves also allow Access Control Policies to be linked to other objects.
VMs for example can be linked with an ACP and a Role.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
 REST-Get-Pc-Roles `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'24-Aug-21 13:40:11' | INFO  | Pulling Roles List.

api_version metadata                                          entities
----------- --------                                          --------
3.1         @{total_matches=9; kind=role; length=9; offset=0} {@{status=; spec=; metadata=}, @{status=; spec=; metadat…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload =@{
    kind="role"
    offset=0
    length=999  
  }

  write-log -message "Pulling Roles List."

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/roles/list"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 
##################################################################
# Update Pc Role
##################################################################

Function REST-Update-Pc-Role {
<#
.SYNOPSIS
Adds a role to prism central for Rback management

.DESCRIPTION
Use REST-Get-Pc-Roles to retrieve, modify and send back using this function.
Prism Element does not have context of these roles.
There are 7-9 built in roles, and custom roles can also be created.
Roles themselves also allow Access Control Policies to be linked to other objects.
VMs for example can be linked with an ACP and a Role.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER RoleName
Name of the role to be created.

.PARAMETER Permissions
Array of UUIDs that need to be added, use REST-Get-Pc-Permissions to retrieve.

.EXAMPLE
REST-Create-Pc-Role `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -RoleName $Role.Name `
  -Permissions $NewPermissionUuids
'19-Dec-21 00:05:53' | INFO  | Pulling Roles List.

status                               spec                                    api_version metadata
------                               ----                                    ----------- --------
@{state=PENDING; execution_context=} @{name=xxx-Linux-Operator; resources=} 3.1         @{owner_reference=; use_categ…

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $RoleObj,
    [parameter(mandatory)] [Array]  $Permissions
  )

  $PsHashPayload =@{
    spec = @{
      name = $RoleObj.status.name
      resources= @{
        permission_reference_list = @()
      }    
    }
    metadata = @{
      kind = "role"
      uuid = $RoleObj.metadata.uuid
      spec_version = $RoleObj.metadata.spec_version
    }
    api_version = "3.1.0"
  }

  foreach ($Permission in $Permissions){
    $object = @{
      kind = "permission"
      uuid = $Permission
    }
    [array]$PsHashPayload.spec.resources.permission_reference_list += $object
  }

  write-log -message "Updating Role '$($RoleObj.metadata.uuid)'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/roles/$($RoleObj.metadata.uuid)"
    Method               = "PUT"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Create Pc Role
##################################################################

Function REST-Create-Pc-Role {
<#
.SYNOPSIS
Adds a Role to Prism Central for RBAC management

.DESCRIPTION
Creates a new role object, please make sure it does not already exist. use REST-Get-Pc-Roles to retrieve.
Prism Element does not have context of these roles.
There are 7-9 built in roles, and custom roles can also be created.
Roles themselves also allow Access Control Policies to be linked to other objects.
VMs for example can be linked with an ACP and a Role.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER RoleName
Name of the role to be created.

.PARAMETER Permissions
Array of UUIDs that need to be added, use REST-Get-Pc-Permissions to retrieve.

.EXAMPLE
REST-Create-Pc-Role `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -RoleName $Role.Name `
  -Permissions $NewPermissionUuids
'19-Dec-21 00:05:53' | INFO  | Pulling Roles List.

status                               spec                                    api_version metadata
------                               ----                                    ----------- --------
@{state=PENDING; execution_context=} @{name=xxx-Linux-Operator; resources=} 3.1         @{owner_reference=; use_categ…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $RoleName,
    [parameter(mandatory)] [Array]  $Permissions
  )

  $PsHashPayload =@{
    spec = @{
      name = $RoleName
      resources= @{
        permission_reference_list = @()
      }    
    }
    metadata = @{
      kind = "role"
    }
    api_version = "3.1.0"
  }

  foreach ($Permission in $Permissions){
    $object = @{
      kind = "permission"
      uuid = $Permission
    }
    [array]$PsHashPayload.spec.resources.permission_reference_list += $object
  }

  write-log -message "Creating Role '$RoleName'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/roles"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Delete Pc Role
##################################################################

Function REST-Delete-Pc-Role {
<#
.SYNOPSIS
Deletes a role to Prism Central for RBAC management

.DESCRIPTION
Deletes a new role object, please make sure it does exist. use REST-Get-Pc-Roles to retrieve.
Prism Element does not have context of these roles.
There are 7-9 built in roles, and custom roles can also be created.
Roles themselves also allow Access Control Policies to be linked to other objects.
VMs for example can be linked with an ACP and a Role.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Delete-Pc-Role `
  -PcClusterIp x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -RoleUuid 6f52a006-392f-40a7-be62-5b402e71b88e
'30-Dec-21 20:34:42' | INFO  | Deleting Role '6f52a006-392f-40a7-be62-5b402e71b88e'

status                                      spec api_version metadata
------                                      ---- ----------- --------
@{state=DELETE_PENDING; execution_context=}      3.1         @{kind=role}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $RoleUuid
  )

  write-log -message "Deleting Role '$RoleUuid'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/roles/$($RoleUuid)"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }

  Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get Prism GPU Profiles
##################################################################

Function REST-Get-Prx-Gpu-Profiles {
<#
.SYNOPSIS
Retrieves the PE Hosts through Prism Central Proxy URL

.DESCRIPTION
Pulls the GPU Profiles from Prism Element, Returns an entity / metadata based object.
This list is useful when building VMs that require a GPU.
Properties from this list are needed to populate REST-Create-Pc-Vm-V3 variables

.PARAMETER PcClusterIp
PcCluster IP is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Cluster Uuid is used for the PRX / Proxy method.

.EXAMPLE
PS C:\Users\gstmigra6> REST-Get-Prx-Gpu-Profiles `
>>       -PcClusterIp $MainVars.AutoDc.PcClusterIp `
>>       -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
>>       -ClusterUuid 0005c7b4-459d-c22c-4c08-88e9a41cf1b8
'29-aug-21 10:35:34' | INFO  | Getting Cluster GPU Profiles

metadata                                               entities
--------                                               --------
@{grand_total_entities=17; total_entities=0; count=17} {@{gpu_config=}, @{gpu_config=}, @{gpu_config=}, @{gpu_config=}…
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid
  )

  write-log -message "Getting Cluster GPU Profiles, using Cluster '$ClusterUuid'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v2.0/hosts/gpu_profiles?proxyClusterUuid=$($ClusterUuid)"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# LCM V2 Build Update Plan
##################################################################

Function REST-Create-Px-Lcm-UpdatePlan {
<#
.SYNOPSIS
Creates an LCM Update plan. Uses next gen LCM API

.DESCRIPTION
API v2.0 based response. 

.PARAMETER AuthHeader
AuthHeader = @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PxClusterIp
PxClusterIp is the name or IP for the Prism Central Cluster.

.PARAMETER Updates Payload to carry the updates

.EXAMPLE
Sorry, No example yet here.
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $Updates
  )

  write-log -message "Creating Pc LCM Update Plan, using a payload containing '$($updates.count)' updates."

  foreach ($Item in $Updates){
    $UpdatePayload = @{
      version = $item.version
      entity_uuid = $item.SoftwareUUID
    }
    [Array]$PsHashPayload += $UpdatePayload
  }

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/lcm/v1.r0.b1/resources/notifications"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# LCM V2 Install Updates
##################################################################

Function REST-Install-Lcm-Updates {
<#
.SYNOPSIS
Installs Updates. Uses next gen LCM API

.DESCRIPTION
Genesis crafted response with the Task UUID.
Genesis API are legacy, crappy APIs, double nested JSONs are required. 

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Updates
Update object, custom built, use 1CN-List-Px-LCM-Updates to build the update table. Essentially a Hash table with 2 properties, verion and Uuid

.EXAMPLE
REST-Install-Pe-Lcm-Updates `
  -PxClusterIp 10.10.0.30 `
  -AuthHeader $BasicHead `
  -Updates $Updates `
  -DarkSiteUrl https://download.nutanix.com/lcm/2.0

'04-dec.-21 17:17:41' | INFO  | Constructing Genesis LCM Install Payload.
'04-dec.-21 17:17:41' | INFO  | Adding '1' Updates Inside the Genesis Payload.

value
-----
{".return": "0be3a6e6-5cf3-4c83-bc8a-74c0c220c28a"}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $Updates
  )

  foreach ($Item in $Updates){
    $UpdatePayload = @{
      version = $item.version
      entity_uuid = $item.SoftwareUUID
    }
    [Array]$entity_update_spec_list += $UpdatePayload
  }

  $PsHashPayload = @{
    entity_update_spec_list = $entity_update_spec_list

  }

  write-log -message "Installing Updates, using a payload containing '$($updates.count)' updates."

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/lcm/v1.r0.b1/operations/update"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add / Set Logon Banner Px
##################################################################

Function REST-Update-Px-LogonBanner {
<#
.SYNOPSIS
Changes the Prism Logon Banner. Update or Add. use REST-Get-Px-LogonBanner function to determine.

.DESCRIPTION
Used fade in and fade out HTML Color coding to change the background color.
Adds logon text to the Prism Central or Prism Element UI

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Name   
Name of the site / location

.PARAMETER PxMode  
PxMode Pe or Pc, changes the logon banner behavior of the title.

.PARAMETER UpdateMode
UpdateMode Update or anything else, changes the method or put or post.

.PARAMETER LdapDomain  
Windows Domain Shows domain name for the logon banner, user instruction to login. 

.PARAMETER CustomerName 
CustomerName Name of the customer used in the logon banner.

.PARAMETER FadeInHtmlColor
FadeInHtmlColor use NONE / Default, to disable, or any HTML Color code.

.PARAMETER FadeOutHtmlColor
FadeOutHtmlColor use NONE / Default, to disable, or any HTML Color code.

.EXAMPLE
REST-Update-Px-LogonBanner `
  -PxClusterIP 10.10.0.30 `
  -AuthHeader $BasicHead `
  -Name MMouse-Home `
  -PxMode PE `
  -UpdateMode Set `
  -LdapDomain MMouse.lan `
  -CustomerName MMouse `
  -FadeInHtmlColor "#666600" `
  -FadeOutHtmlColor "#cccc00"

'04-dec.-21 18:34:18' | INFO  | Applying UI Customization 'title' using value 'Use UPN based MMouse.lan credentails'
'04-dec.-21 18:34:19' | INFO  | Applying UI Customization 'product_title' using value 'PE - Site MMouse-Home'
'04-dec.-21 18:34:19' | INFO  | Applying UI Customization 'disable_2048' using value 'True'
'04-dec.-21 18:34:19' | INFO  | Applying UI Customization 'autoLogoutGlobal' using value '900000'
'04-dec.-21 18:34:19' | INFO  | Applying UI Customization 'welcome_banner' using value 'Site MMouse-Home'
'04-dec.-21 18:34:19' | INFO  | Applying UI Customization 'color_in' using value '#666600'
'04-dec.-21 18:34:20' | INFO  | Applying UI Customization 'color_out' using value '#cccc00'
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $Name,  
    [parameter(mandatory)] [string] $PxMode,
    [parameter(mandatory)] [string] $UpdateMode,
    [parameter(mandatory)] [string] $LdapDomain,
    [parameter(mandatory)] [string] $CustomerName,
    [parameter(mandatory)] [string] $FadeInHtmlColor,
    [parameter(mandatory)] [string] $FadeOutHtmlColor
  )


  if ($UpdateMode -eq "Update"){
    $Method = "PUT"
  } else {
    $Method = "POST"
  }

  if ($PxMode -eq "Pc"){
    $LoginScreeenTitle        = "Use UPN based $LdapDomain credentails"
    $LoginScreeenProductTitle = "Self - Service - $($CustomerName)"
  } else {
    $LoginScreeenTitle        = "Use UPN based $LdapDomain credentails"
    $LoginScreeenProductTitle = "PE - Site $Name" 
  }

  $PsHashPayload = @(
    @{
      type  = "custom_login_screen"
      key   = "title"
      value = $LoginScreeenTitle
    }
    @{
      type  = "custom_login_screen"
      key   = "product_title"
      value = $LoginScreeenProductTitle
    }
    @{
      type      = "UI_CONFIG"
      username  = "system_data"
      key       = "disable_2048"
      value     = $true
    }
    @{
      type      = "UI_CONFIG"
      key       = "autoLogoutGlobal"
      value     = 900000
    }
    #@{
    #  type      = "UI_CONFIG"
    #  key       = "welcome_banner"
    #  value     = "Site $Name"
    #}
  )
  if ($FadeInHtmlColor.Length -ne 0 -or $FadeInHtmlColor -notmatch "NONE|NA|N/A|Default"){
    $PsHashPayload += @{
      type      = "custom_login_screen"
      key       = "color_in"
      value     = $FadeInHtmlColor
    }  
  }
  if ($FadeInHtmlColor.Length -ne 0 -or $FadeInHtmlColor -notmatch "NONE|NA|N/A|Default"){
    $PsHashPayload += @{
      type      = "custom_login_screen"
      key       = "color_out"
      value     = $FadeOutHtmlColor
    }  
  }

  foreach ($iten in $PsHashPayload){

    write-log -message "Applying UI Customization '$($iten.key)' using value '$($iten.value)'"

    $RequestPayload = @{
      Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/application/system_data"
      Method               = $Method
      Body                 = $iten
      Headers              = $AuthHeader
    }

    $Output = Ps-Invoke-Rest `
      -HashArguments $RequestPayload `
      -name (Get-FunctionName) `
      -Retry 1 `
      -LastError $False
  }
} 

##################################################################
# Get Logon Banner Px
##################################################################

Function REST-Get-Px-LogonBanner {
<#
.SYNOPSIS
Retrieves the Prism Logon Banner. Use this function to determine Update or Add for REST-Update-Px-LogonBanner

.DESCRIPTION
Pulls the current UI Customization $AlreadyApplied = Returndata | where {$_.type -eq "custom_login_screen"}

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-LogonBanner `
  -PxClusterIP 10.10.0.32 `
  -AuthHeader $BasicHead
'04-dec.-21 18:36:03' | INFO  | Pulling Current UI Customization

username           : system_data
key                : num_of_shares_per_nvm
type               : CONFIG
value              : 100
updatedTimeInUsecs : 1629203369064000
identifier         :
updatedByConfig    : True

username           : system_data
key                : color_in
type               : CUSTOM_LOGIN_SCREEN
value              : #666600
updatedTimeInUsecs : 1638639272713000
identifier         :
updatedByConfig    : False

username           : system_data
key                : uiEbrowser
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Pulling Current UI Customization"

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/application/system_data"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Set VM Power State
##################################################################

Function REST-Set-Pe-VM-PowerState {
<#
.SYNOPSIS
Changes the power state of a virtual machine, uses Prism Element 2.0 API

.DESCRIPTION
This API uses a fire and forget method, use the task ID returned, to monitor the task for success or completion.
acpi methods are known to be broken, Windows VMs are famous for not shutting down on ACPI Commands in Nutanix.
Weirdly enough, open the console and it will. 

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER VmUuid  
VmUuid UUID of the VM Object

.PARAMETER State
State Possible Power Options are 'off', 'on', 'acpi_shutdown', 'acpi_reboot' and 'reset'

.EXAMPLE
REST-Set-Pe-VM-PowerState `
  -PeClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -VmUuid $VmUuid `
  -State "Off"
'16-Sep-21 19:11:18' | INFO  | Sending Power State 'Off' to 'dca3f5d9-43d3-48a7-99dc-f9595e651339'

task_uuid
---------
efc46bf3-5458-4def-9ae0-a893a8553dd4
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmUuid,
    [parameter(mandatory)] [string] $State
  )

  $PsHashPayload = @{
    transition = $State

  }

  write-log -message "Sending Power State '$State' to '$VMuuid'"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v2.0/vms/$($VmUuid)/set_power_state"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Set VM Description
##################################################################

Function REST-Set-Pe-VM-Description {
<#
.SYNOPSIS
Sets the description of a virtual machine, uses Prism Element 2.0 API

.DESCRIPTION
This API uses a fire and forget method, use the task ID returned, to monitor the task for success or completion.
Single line description, no field length, carriage return does not seem possible.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER VmUuid  
VmUuid UUID of the VM Object

.PARAMETER Description
Description text of the VM

.EXAMPLE
REST-Set-Pe-VM-Description `
  -PeClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -VmUuid $VmUuid `
  -Description "ElferinkIsNoMore"
'16-Sep-21 19:20:50' | INFO  | Setting VM Description on 'dca3f5d9-43d3-48a7-99dc-f9595e651339'

task_uuid
---------
200313cb-df79-44d8-8177-05952f454c9b
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmUuid,
    [parameter(mandatory)] [string] $Description
  )

  $PsHashPayload = @{
    description = $Description
  }

  write-log -message "Setting VM Description on '$VMuuid'"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v2.0/vms/$($VmUuid)"
    Method               = "PUT"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Set VM BootMode
##################################################################

Function REST-Set-Pe-VM-BootMode {
<#
.SYNOPSIS
Sets the boot mode of a VM., uses Prism Element 2.0 API

.DESCRIPTION
This API uses a fire and forget method, use the task ID returned, to monitor the task for success or completion.
Hardware Virtualization locks the VM to the host, VM cannot migrate while powered on.
VM cannot be powered on after creation, not compatible with Secureboot and Sysprep, as sysprep always creates IDE drives if secureboot is not enabled.
See REST-Create-Pc-Vm-V3 which also supports Bootmode including sysprep.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER VmUuid  
VmUuid UUID of the VM Object

.PARAMETER BootMode
Bootmode '0' means legacy boot, '1' means uefi only boot, '2' means secure boot, '3' means secure boot with credential guard

.EXAMPLE
REST-Set-Pe-VM-BootMode `
  -PeClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -VmUuid $VmUuid `
  -BootMode 0
'16-Sep-21 19:20:50' | INFO  | Current BootMode: '1'

task_uuid
---------
200313cb-df79-44d8-8177-05952f454c9b
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmUuid,
    [parameter(mandatory)] [int]    $BootMode
  )

  Switch ($BootMode){
    0 {$uefi = "false";$secureboot = "false";$machine_type = ""   ; $credVault ="false"}
    1 {$uefi = "true" ;$secureboot = "false";$machine_type = "q35"; $credVault ="false"}
    2 {$uefi = "true" ;$secureboot = "true" ;$machine_type = "q35"; $credVault ="false"}
    3 {$uefi = "true" ;$secureboot = "true" ;$machine_type = "q35"; $credVault ="true"}
  }

  $PsHashPayload = @{
    boot = @{
      uefi_boot = $uefi
      secure_boot = $secureboot
      hardware_virtualization = $credVault
    }
    machine_type = $machine_type
  }

  write-log -message "BootMode: '0' means legacy boot."
  write-log -message "BootMode: '1' means uefi only boot."
  write-log -message "BootMode: '2' means secure boot."
  write-log -message "BootMode: '3' means secure boot with credential guard."
  write-log -message "Current BootMode: '$BootMode'"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v2.0/vms/$($VmUuid)"
    Method               = "PUT"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Query Pe Cluster V2
##################################################################

Function REST-Get-Pe-Cluster-Detail {
<#
.SYNOPSIS
Sets the description of a virtual machine, uses Prism Element 1.0 API

.DESCRIPTION
Returns the Cluster detail based on the V1 API.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Uuid of the cluster to query the detailed object. 

.EXAMPLE
REST-Get-Pe-Cluster-Detail `
  -PeClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $Mainvars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -ClusterUuid $MyCluster.metadata.uuid
'18-Sep-21 11:11:49' | INFO  | Executing Pe Detail Cluster Query, using Uuid '0005aa62-797b-1f9a-6c01-48df37c63270'

id                                    : 0005aa62-797b-1f9a-6c01-48df37c63270::7782581754623570544
uuid                                  : 0005aa62-797b-1f9a-6c01-48df37c63270
clusterIncarnationId                  : 1594714805182362
clusterUuid                           : 0005aa62-797b-1f9a-6c01-48df37c63270
name                                  : 
clusterExternalIPAddress              : 
clusterExternalAddress                : 
clusterFullyQualifiedDomainName       :
isNSEnabled                           : 
clusterExternalDataServicesIPAddress  : 
clusterExternalDataServicesAddress    : 
segmentedIscsiDataServicesIPAddress   :
segmentedIscsiDataServicesAddress     :
clusterMasqueradingIPAddress          :
clusterMasqueradingAddress            :
clusterMasqueradingPort               :
timezone                              : Europe/Amsterdam
supportVerbosityType                  : BASIC_COREDUMP
operationMode                         : Normal
encrypted                             : True
clusterUsageWarningAlertThresholdPct  : 75
clusterUsageCriticalAlertThresholdPct : 90
storageType                           : mixed
clusterFunctions                      : {NDFS}
isLTS                                 : True
isRegisteredToPC                      : True
numNodes                              : 3
blockSerials                          : {CZ202301X8, CZ202301X4, CZ202301X3}
version                               : 5.20.0.1
fullVersion                           : el7.3-release-euphrates-5.20.0.1-stable-f5e54bf50b9b92d1e27560e422629e322968a3e
                                        0
targetVersion                         : 5.20.0.1
externalSubnet                        : xxxxxxx/255.255.255.0
externalAddress                       : {@{ipv4=xxxxx/255.255.255.0}}
internalSubnet                        : 192.168.5.0/255.255.255.128
internalAddress                       : {@{ipv4=xxxx/255.255.255.128}}
nccVersion                            : ncc-4.2.0.2
enableLockDown                        : False
enablePasswordRemoteLoginToCluster    : True
fingerprintContentCachePercentage     : 100
ssdPinningPercentageLimit             : 25
enableShadowClones                    : True
enableRf1Container                    : False
globalNfsWhiteList                    : {}
globalNfsWhiteListAddress             : {}
nameServers                           : {xxxxx}
nameServersList                       : {@{ipv4=10.230.253.2}, @{ipv4=10.230.197.9}}
ntpServers                            : {xx, xx, xx, xx}
ntpServersList                        : {@{hostname=xx}, @{hostname=xx},
                                        @{hostname=xx}, @{hostname=xx}…}
serviceCenters                        : {}
httpProxies                           : {}
rackableUnits                         : {@{id=24; rackableUnitUuid=5d69208b-321d-4eac-b1e5-0102ef7dbc67;
                                        model=UseLayout; modelName=HPE DX360-4 G10; location=; serial=CZ202301X8;
                                        positions=System.Object[]; nodes=System.Object[]; nodeUuids=System.Object[]},
                                        @{id=29; rackableUnitUuid=26c28bc5-ae48-422f-bb04-52a4aa28e5ad;
                                        model=UseLayout; modelName=HPE DX360-4 G10; location=; serial=CZ202301X4;
                                        positions=System.Object[]; nodes=System.Object[]; nodeUuids=System.Object[]},
                                        @{id=33; rackableUnitUuid=23d8284c-cfa0-4cd8-8935-bd6d4c0f3473;
                                        model=UseLayout; modelName=HPE DX360-4 G10; location=; serial=CZ202301X3;
                                        positions=System.Object[]; nodes=System.Object[]; nodeUuids=System.Object[]}}
publicKeys                            : {@{name=Nutanix; key=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDjM+OdMBRTj/Uv+mD/q9
                                        g/DvGkRxSyZbWwcGraPdwt275K/ve63SUf3QlJpVXN/CJojzxGCJwAKR6qUHh3PCUcWz8FYsfb3cGC7
                                        YM0i0kNa/bC179d0o/HQqKD1xQlsfefr3fEFeLyObduXpM/2lcwpOnKAjBg0zV01NJ45HG/RHeQqjrX
                                        AJAZsHkJkB23HVwH4PoCBd0ibnWpdBztEprc+zpSaXSfbiyCPPgwgfDW/R2k1DREP+sNSE57jWud9sa
                                        c3qxuxRtVZfj7hcVzF5ToShTGdYor/8OeaghUlGBKp+fkv5VX61ki0nTMcinPcKy9GGZgNRKVd0Ks90
                                        ohZqXT}, @{name=Gateway; key=ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAu+fMkr2mG3H+fm
                                        ztwUGt3+xlAamoOOdA8g8+igvM8WhzA+p6d4gDMmq+LEyBSrum3I9wyTIrfwTbtUtz1LyKNd+5LgdMf
                                        GjTo9rw/Q92xQSvuuRHLX19MV8ozVQhfwUHq2Sh4a26loVqJl57jvl9Tsv1L4/KkR3vX96hImcF3G1C
                                        uyeKpAK2HUsCpP60qbsZ8i2LDH+qDPW6BlsAvqtl8TDu0Tiy1DXLVclga6HOsP6DWm5hvNAL4u9uH/5
                                        siWLyYRienO/tsK8s7ymf0p0lRZDzHHUdR0UD0WJC0LR6FPG2YbS+BcGG18NRXixsooeL0nx3DUydDD
                                        PJqKSkJTtTeQ== rsa-key-20210619}}
smtpServer                            :
hypervisorTypes                       : {kKvm}
clusterRedundancyState                : @{currentRedundancyFactor=2; desiredRedundancyFactor=2; redundancyStatus=}
multicluster                          : False
cloudcluster                          : False
hasSelfEncryptingDrive                : False
isUpgradeInProgress                   : False
securityComplianceConfig              : @{schedule=DAILY; enableAide=False; enableCore=False;
                                        enableHighStrengthPassword=False; enableBanner=False;
                                        enableKernelMitigations=False; enableSNMPv3Only=False}
hypervisorSecurityComplianceConfig    : @{schedule=DAILY; enableAide=False; enableCore=False;
                                        enableHighStrengthPassword=False; enableBanner=False; enableKernelMitigations=}
hypervisorLldpConfig                  : @{enableLldpTx=True}
clusterArch                           : X86_64
isSspEnabled                          : False
iscsiConfig                           :
domain                                :
nosClusterAndHostsDomainJoined        : False
allHypervNodesInFailoverCluster       : False
credential                            :
stats                                 : @{hypervisor_avg_io_latency_usecs=0; num_read_iops=3;
                                        hypervisor_write_io_bandwidth_kBps=0; timespan_usecs=30000000;
                                        controller_num_read_iops=4; read_io_ppm=146575; controller_num_iops=534;
                                        total_read_io_time_usecs=-1; controller_total_read_io_time_usecs=37394;
                                        replication_transmitted_bandwidth_kBps=0; hypervisor_num_io=0;
                                        controller_total_transformed_usage_bytes=-1; hypervisor_cpu_usage_ppm=318229;
                                        controller_num_write_io=15897; avg_read_io_latency_usecs=-1;
                                        content_cache_logical_ssd_usage_bytes=0;
                                        controller_total_io_time_usecs=29735061;
                                        controller_total_read_io_size_kbytes=5824; controller_num_seq_io=-1;
                                        controller_read_io_ppm=7987; content_cache_num_lookups=1603;
                                        controller_total_io_size_kbytes=165192; content_cache_hit_ppm=965065;
                                        controller_num_io=16025; hypervisor_avg_read_io_latency_usecs=0;
                                        content_cache_num_dedup_ref_count_pph=100; num_write_iops=20;
                                        controller_num_random_io=-1; num_iops=24;
                                        replication_received_bandwidth_kBps=0; hypervisor_num_read_io=0;
                                        hypervisor_total_read_io_time_usecs=0; controller_avg_io_latency_usecs=1855;
                                        hypervisor_hyperv_cpu_usage_ppm=-1; num_io=730; controller_num_read_io=128;
                                        hypervisor_num_write_io=0; controller_seq_io_ppm=-1;
                                        controller_read_io_bandwidth_kBps=194; controller_io_bandwidth_kBps=5506;
                                        hypervisor_hyperv_memory_usage_ppm=-1; hypervisor_timespan_usecs=30104484;
                                        hypervisor_num_write_iops=0; replication_num_transmitted_bytes=0;
                                        total_read_io_size_kbytes=848; hypervisor_total_io_size_kbytes=0;
                                        avg_io_latency_usecs=280; hypervisor_num_read_iops=0;
                                        content_cache_saved_ssd_usage_bytes=0;
                                        controller_write_io_bandwidth_kBps=5312; controller_write_io_ppm=992012;
                                        hypervisor_avg_write_io_latency_usecs=0;
                                        hypervisor_total_read_io_size_kbytes=0; read_io_bandwidth_kBps=28;
                                        hypervisor_esx_memory_usage_ppm=-1; hypervisor_memory_usage_ppm=293800;
                                        hypervisor_num_iops=0; hypervisor_io_bandwidth_kBps=0;
                                        controller_num_write_iops=529; total_io_time_usecs=204829;
                                        hypervisor_kvm_cpu_usage_ppm=318229; content_cache_physical_ssd_usage_bytes=0;
                                        controller_random_io_ppm=-1; controller_avg_read_io_size_kbytes=45;
                                        total_transformed_usage_bytes=-1; avg_write_io_latency_usecs=-1;
                                        num_read_io=107; write_io_bandwidth_kBps=592;
                                        hypervisor_read_io_bandwidth_kBps=0; random_io_ppm=-1;
                                        content_cache_num_hits=1547; total_untransformed_usage_bytes=-1;
                                        hypervisor_total_io_time_usecs=0; num_random_io=-1;
                                        hypervisor_kvm_memory_usage_ppm=293800;
                                        controller_avg_write_io_size_kbytes=10;
                                        controller_avg_read_io_latency_usecs=292; num_write_io=623;
                                        hypervisor_esx_cpu_usage_ppm=-1; total_io_size_kbytes=18612;
                                        io_bandwidth_kBps=620; content_cache_physical_memory_usage_bytes=25218442704;
                                        replication_num_received_bytes=0; controller_timespan_usecs=30000000;
                                        num_seq_io=-1; content_cache_saved_memory_usage_bytes=0; seq_io_ppm=-1;
                                        write_io_ppm=853424; controller_avg_write_io_latency_usecs=1868;
                                        content_cache_logical_memory_usage_bytes=25218442704}
usageStats                            : @{data_reduction.overall.saving_ratio_ppm=10524000;
                                        storage.reserved_free_bytes=0; storage_tier.das-sata.usage_bytes=532681867264;
                                        data_reduction.compression.saved_bytes=23438974976;
                                        data_reduction.saving_ratio_ppm=1007586;
                                        data_reduction.erasure_coding.post_reduction_bytes=3089440743424;
                                        storage_tier.ssd.pinned_usage_bytes=0; storage.reserved_usage_bytes=0;
                                        data_reduction.erasure_coding.saving_ratio_ppm=1000000;
                                        data_reduction.thin_provision.saved_bytes=28972386803712;
                                        storage_tier.das-sata.capacity_bytes=65762709682914;
                                        storage_tier.das-sata.free_bytes=65230027815650;
                                        storage.usage_bytes=2036788690944;
                                        data_reduction.erasure_coding.saved_bytes=0;
                                        data_reduction.compression.pre_reduction_bytes=3112879718400;
                                        storage_tier.das-sata.pinned_bytes=0; storage.rebuild_capacity_bytes=-1;
                                        storage_tier.das-sata.pinned_usage_bytes=0;
                                        data_reduction.pre_reduction_bytes=3112879718400;
                                        storage_tier.ssd.capacity_bytes=3824277550692;
                                        data_reduction.clone.saved_bytes=428008507392;
                                        storage_tier.ssd.free_bytes=2320170727012;
                                        data_reduction.dedup.pre_reduction_bytes=2847226730534;
                                        data_reduction.erasure_coding.pre_reduction_bytes=3089440743424;
                                        storage.capacity_bytes=69586987233606;
                                        data_reduction.dedup.post_reduction_bytes=2847226730534;
                                        data_reduction.clone.saving_ratio_ppm=1115831;
                                        storage.logical_usage_bytes=3409943461888;
                                        data_reduction.saved_bytes=23438974976; storage.free_bytes=67550198542662;
                                        storage_tier.ssd.usage_bytes=1504106823680;
                                        data_reduction.compression.post_reduction_bytes=3089440743424;
                                        data_reduction.post_reduction_bytes=3089440743424;
                                        data_reduction.dedup.saved_bytes=0;
                                        data_reduction.overall.saved_bytes=29423834286080;
                                        data_reduction.thin_provision.post_reduction_bytes=1829330543616;
                                        data_reduction.thin_provision.saving_ratio_ppm=16837699;
                                        data_reduction.compression.saving_ratio_ppm=1007586;
                                        data_reduction.dedup.saving_ratio_ppm=1000000;
                                        storage_tier.ssd.pinned_bytes=0; storage.reserved_capacity_bytes=0;
                                        data_reduction.thin_provision.pre_reduction_bytes=30801717347328}
enforceRackableUnitAwarePlacement     : False
disableDegradedNodeMonitoring         : False
commonCriteriaMode                    : False
enableOnDiskDedup                     :
managementServers                     :
faultToleranceDomainType              : NODE
thresholdForStorageThinProvision      :
recycleBinDTO                         : @{recycleBinTTLSecs=86400}

#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid
  )

  write-log -message "Pulling Pe Detail Cluster, using Uuid '$ClusterUuid'"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/clusters/$ClusterUuid"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Query Pe Cluster V2
##################################################################

Function REST-List-Pe-Clusters {
<#
.SYNOPSIS
Sets the description of a virtual machine, uses Prism Element 1.0 API

.DESCRIPTION
Lists Pe Clusters using the V1 API. This is a Prism Element Only API.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-List-Pe-Clusters `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'18-Sep-21 11:16:44' | INFO  | Listing Pe Clusters

metadata                                                                                                            entities
--------                                                                                                            --------
@{grandTotalEntities=1; totalEntities=1; filterCriteria=; sortCriteria=; page=1; count=1; startIndex=1; endIndex=1} {@{id=0005aa62-797b-1f9a-6c01-48df37c63270::7782581754623570544; uuid=0005aa62-797b-1f9a-6c01-48df37c63270; clusterIncarnationId=159471…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Listing Pe Clusters"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/clusters"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Delete remote site using PRX
##################################################################

Function REST-Delete-Prx-Remote-Site {
<#
.SYNOPSIS
Deletes remote site through proxy.

.DESCRIPTION
Used V1 API using cluster Proxy URI

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER RemoteSiteName
RemoteSiteName Name of the remote site.

.PARAMETER ClusterUuid
ClusterUuid target cluster that is used by Pc as its proxy target.

.EXAMPLE

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $RemoteSiteName,
    [parameter(mandatory)] [string] $ClusterUuid
  )

  write-log -message "Remote Site Delete '$($RemoteSiteName)' via PC Cluster '$($ClusterUuid)'"

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/remote_sites/$($RemoteSiteName)?proxyClusterUuid=$($ClusterUUID)"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

} 

##################################################################
# Delete remote site
##################################################################

Function REST-Delete-Pe-Remote-Site {
<#
.SYNOPSIS
Deletes remote site in PE Data Protection.

.DESCRIPTION
Used V1 API, executes local to the cluster. Remote site should not be in use once deleted.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER RemoteSiteName
RemoteSiteName Name of the remote site.

.EXAMPLE
REST-Delete-Pe-Remote-Site `
  -PeClusterIP $MainVars.cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -RemoteSiteName "cccc-xxxx"
'16-Sep-21 21:13:00' | INFO  | Deleting Remote Site :'ccc-xxx'

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $RemoteSiteName
  )

  write-log -message "Deleting Remote Site :'$($RemoteSiteName)'"

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/remote_sites/$($RemoteSiteName)"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Delete Remote Site Snapshots
##################################################################

Function REST-Delete-Pe-ProtectionDomain-RemoteSnapshots {
<#
.SYNOPSIS
Deletes Snapshot for a remote site its protection domain, meaning Remote Snaps, not local

.DESCRIPTION
Please be careful deleting snapshots.
Deletes Snapshot for a remote site its protection domain, meaning Remote Snaps, not local

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER RemoteSiteName
RemoteSiteName Name of the remote site.

.PARAMETER ProtectionDomainName
ProtectionDomainName Name of the protection domain.

.PARAMETER SnapShotId
SnapShotId ID of the snap shot, used different commands to list.

.EXAMPLE
Sorry, No Example yet.
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $RemoteSiteName,
    [parameter(mandatory)] [string] $ProtectionDomainName,
    [parameter(mandatory)] [INT]    $SnapShotId
  )

  write-log -message "Remote Site target       : '$($RemoteSiteName)'"
  write-log -message "Protection Domain target : '$($ProtectionDomainName)'"
  write-log -message "Snapshot ID              : '$($SnapShotId)'" 

  $PsHashPayload = @{
    drSnapshotIdsMap = @{
      $ProtectionDomainName = @(
        $SnapShotId
      )
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/remote_sites/$($RemoteSiteName)/dr_snapshots/remove_list"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Get Pc Software Components
##################################################################

Function REST-Get-Pe-PcSoftware {
<#
.SYNOPSIS
Pulls the Pe software repository for the current status of PC software payloads available for deployment.

.DESCRIPTION
Uses V1 API, simple response.
Data includes their download status and hash values.

.PARAMETER PeClusterIP
PeClusterIp is the name or IP for the Prism Element

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pe-PcSoftware `
  -PeClusterIP $MainVars.cluster.PeClusterIP `
  -AuthHeader $Mainvars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'19-Sep-21 11:21:28' | INFO  | Getting API PC Software status.

entities
--------
{@{name=pc.2021.8.0.1; version=pc.2021.8.0.1; md5Sum=fac57cc767d2b0cb4227de36fdda006e; gpgSignature=; totalSizeInBytes…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  Write-Log -message "Getting API PC Software status."


  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/upgrade/prism_central_deploy/softwares"
    Method               = "GET"
    Headers              = $AuthHeader
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Unmount Pe VM CDRom Drive
##################################################################

Function REST-Unmount-Pe-VmCdRom {
<#
.SYNOPSIS
Pulls the Pe software repository for the current status of PC software payloads available for deployment.

.DESCRIPTION
Uses V1 API, simple response.
Data includes their download status and hash values.

.PARAMETER PeClusterIP
PeClusterIp is the name or IP for the Prism Element

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pe-PcSoftware `
  -PeClusterIP $MainVars.cluster.PeClusterIP `
  -AuthHeader $Mainvars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'19-Sep-21 11:21:28' | INFO  | Getting API PC Software status.

entities
--------
{@{name=pc.2021.8.0.1; version=pc.2021.8.0.1; md5Sum=fac57cc767d2b0cb4227de36fdda006e; gpgSignature=; totalSizeInBytes…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmUuid,
    [parameter(mandatory)] [object] $CdRomObj
  )

  $PsHashPayload = @{
    "vm_disks" = @(@{
      "disk_address" = @{
        "vmdisk_uuid"  = "$($cdrom.disk_address.device_uuid)"
        "device_index" = $($cdrom.disk_address.device_index)
        "device_bus"   = "$($cdrom.disk_address.device_bus)"
      }
      "flash_mode_enabled" = $false
      "is_cdrom" = $true
      "is_empty" = $true
    })
  }

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/upgrade/prism_central_deploy/softwares"
    Method               = "PUT"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Update Pe VM Disk Size
##################################################################

Function REST-Change-Pe-VmDiskSize {
<#
.SYNOPSIS
Updates the disk size of the SCSI ID specified. Size in GB as input

.DESCRIPTION
Updates the disk object for the VM.

.PARAMETER PeClusterIP
PeClusterIp is the name or IP for the Prism Element

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER VmDetailObj  
VmDetailObj API V2 Detailed object, use REST-Get-Px-VM-V2-Detail as input

.PARAMETER SizeGb
SizeGb size in GB integer

.PARAMETER ScsiId  
ScsiId ID of the Target disk, integer.

.EXAMPLE
REST-Change-Pe-VmDiskSize `
  -PeClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -VmDetailObj $VmDetail `
  -SizeGb 400 `
  -ScsiId 1
'19-Sep-21 16:11:16' | INFO  | Building a DiskObject
'19-Sep-21 16:11:16' | INFO  | Building Credential object
'19-Sep-21 16:11:16' | INFO  | Setting '400' GB Disk to VM '3a05ba8f-0759-460d-bdbe-e7784c72826a'
'19-Sep-21 16:11:16' | INFO  | This VM has '2' disk
'19-Sep-21 16:11:16' | INFO  | Setting new disk size on VM 'XXXX-NT8000'
'19-Sep-21 16:11:16' | INFO  | Changing old size '322122547200' Bites
'19-Sep-21 16:11:16' | INFO  | Into new size '429496729600' Bites
'19-Sep-21 16:11:16' | INFO  | Updating SCSI index '1'
'19-Sep-21 16:11:16' | INFO  | Converting to REST Payload
'19-Sep-21 16:11:16' | INFO  | Captain our payload is empty....

task_uuid
---------
8204a2e3-cf3e-406c-bd8a-f6c3665793b8
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $VmDetailObj,
    [parameter(mandatory)] [INT]    $SizeGb,
    [parameter(mandatory)] [INT]    $ScsiId
  )

  [array]$vmdisks = $VmDetailObj.vm_disk_info | where {$_.is_cdrom -eq $false}

  write-log -message "Building a DiskObject"

  $vm_disks = @{
    vm_disks = $vmdisks
  }

  write-log -message "Building Credential object"
  write-log -message "Setting '$($SizeGB)' GB Disk to VM '$($VMDetail.uuid)'" 

  [decimal] $Oldsize = ($vm_disks.vm_disks | Where-Object {$_.disk_address.device_index -eq $SCSIID}).size
  [decimal] $Newsize = ((($sizeGB * 1024) * 1024 ) * 1024 )

  if ($Oldsize -ge $Newsize){

    Write-log -message "This Function can only increase, old size is '$Oldsize' bites"
    Write-log -message "Requested size is '$Newsize' bites" -sev "WARN" -errorcode "00139"
    
  } else {

    Write-log -message "This VM has '$($vm_disks.vm_disks.count)' disk"
    Write-log -message "Setting new disk size on VM '$($vmdetail.name)'"
    Write-log -message "Changing old size '$($Oldsize)' Bites"
    Write-log -message "Into new size '$($Newsize)' Bites"

    $vm_disks.vm_disks | % {

      $vm_disk_create = @{
        storage_container_uuid = $_.storage_container_uuid
      }

      if ($SCSIID -eq $_.disk_address.device_index -and $_.disk_address.device_bus -match "scsi"){
         $vm_disk_create | add-member Noteproperty size $Newsize

         write-log -message "Updating SCSI index '$($SCSIID)'"

      } else {
         $vm_disk_create | add-member Noteproperty size $Oldsize
      }
     
      $_ | add-member Noteproperty vm_disk_create $vm_disk_create -force
  
      $_.psobject.members.Remove("source_disk_address")
      $_.psobject.members.Remove("storage_container_uuid")
      $_.psobject.members.Remove("size")

    }

    Write-log -message "Converting to REST Payload"

    if ($payload -eq $null){

      write-log -message "Captain our payload is empty...."

    }

    $RequestPayload = @{
      Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v2.0/vms/$($VmDetailObj.uuid)/disks/update"
      Method               = "PUT"
      Headers              = $AuthHeader
      Body                 = $vm_disks
    }
  
    Return Ps-Invoke-Rest `
      -HashArguments $RequestPayload `
      -name (Get-FunctionName)
  }
}

##################################################################
# Add Virtual Machine Disks V2 Api
##################################################################

Function REST-Add-Pe-VmDisk {
<#
.SYNOPSIS
Adds a disk to a Prism Element Virtual Machine.

.DESCRIPTION
Prism Element only, adds an extra disk to the VM.
Uses the same storage container as the VM itself is stored.
Requires the detailed VM object to be inserted.

.PARAMETER PeClusterIP
PeClusterIp is the name or IP for the Prism Element

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER VmDetailObj  
VmDetailObj API V2 Detailed object, use REST-Get-Px-VM-V2-Detail as input

.PARAMETER SizeGb
SizeGb size in GB integer

.PARAMETER DiskType
DiskType sata or scsi

.EXAMPLE
REST-Add-Pe-VmDisk `
  -PeClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -VmDetailObj $VmDetail `
  -SizeGb 450
'19-Sep-21 16:15:35' | INFO  | Adding a '450' GB Disk to VM '3a05ba8f-0759-460d-bdbe-e7784c72826a'
'19-Sep-21 16:15:35' | INFO  | Assigning SCSI index '2'

task_uuid
---------
c2d7606e-62bc-42b6-95c7-82e53c64f067
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $VmDetailObj,
    [parameter(mandatory)] [INT]    $SizeGb,
                           [string] $DiskType = "scsi"
  )

  if ($disktype -notmatch "sata|ide|scsi"){
    $DiskType = "scsi"
  }
  write-log -message "Adding a '$($SizeGB)' GB Disk, type: '$DiskType' inside VM '$($VmDetailObj.uuid)'"

  $SizeBytes = ((($sizeGB * 1024) * 1024 ) * 1024 )
  $VmDetailObj.vm_disk_info | where {$_.disk_address.device_bus -match $DiskType } | % { [array]$BusIndex += $_.disk_address.device_index}
  $ContainerUuid = ($VmDetailObj.vm_disk_info | where {$_.disk_address.device_bus -match $DiskType  -and $_.storage_container_uuid } | select-object -first 1).storage_container_uuid
  $FreeIndex = [INT]($BusIndex | sort-object | select-object -last 1 ) + 1 

  write-log -message "Assigning '$DiskType' index '$($FreeIndex)'"

  if ($SizeBytes -ne 0){

    $PsHashPayload = @{
      vm_disks = @(@{
        is_cdrom = $False
        disk_address =@{
          device_bus = $DiskType
          device_index = $FreeIndex
        }
        vm_disk_create = @{
          storage_container_uuid = $ContainerUuid
          size = $SizeBytes
        }
      })
    }
  
    $RequestPayload = @{
      Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v2.0/vms/$($VmDetailObj.uuid)/disks/attach"
      Method               = "POST"
      Body                 = $PsHashPayload
      Headers              = $AuthHeader
    }
  
    Return Ps-Invoke-Rest `
      -HashArguments $RequestPayload `
      -name (Get-FunctionName)
  }
}

##################################################################
# Get Prism Element Networks API V 0.8
##################################################################

Function REST-List-PE-Networks-V08 {
<#
.SYNOPSIS
Pulls Prism Element networks based on the V0.8 API

.DESCRIPTION
Uses V0.8 API, simple response. Used for Renaming networks etc.

.PARAMETER PeClusterIP
PeClusterIp is the name or IP for the Prism Element

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-PE-Networks-V08 `
  -PeClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead

metadata                                 entities
--------                                 --------
@{grandTotalEntities=8; totalEntities=8} {@{logicalTimestamp=7; vlanId=115; ipConfig=; uuid=d9ef5d91-1499-4aab-9f84-91e61867edcf; virtualSwitchUuid=bf01c5ff-525f-4e2d-aa02-5868e7970f48; name=xxxxx-115-PaloAlto_Sync; vswitchName=br0}, @{logicalTimes…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/api/nutanix/v0.8/networks"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Prism Element Network API V 0.8 Detail
##################################################################

Function REST-Get-PE-Network-V08-Detail {
<#
.SYNOPSIS
Pulls Prism Element networks based on the V0.8 API

.DESCRIPTION
Uses V0.8 API, simple response. Used for Renaming networks etc.

.PARAMETER PeClusterIP
PeClusterIp is the name or IP for the Prism Element

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-PE-Network-V08-Detail `
  -PeClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -NetworkUuid $networks.entities[0].uuid

logicalTimestamp  : 7
vlanId            : 115
ipConfig          : @{prefixLength=0; ipamEnabled=False; freeIps=-1; assignedIps=-1; numMacs=2; dhcpOptions=; pool=System.Object[]}
uuid              : d9ef5d91-1499-4aab-9f84-91e61867edcf
virtualSwitchUuid : bf01c5ff-525f-4e2d-aa02-5868e7970f48
name              : xxxxxx-115-PaloAlto_Sync
vswitchName       : br0
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $NetworkUuid
  )

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/api/nutanix/v0.8/networks/$NetworkUuid"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `

}

##################################################################
# Update Prism Element Network API V 0.8 Detail
##################################################################

Function REST-Update-PE-Network-V08-Obj {
<#
.SYNOPSIS
Updates Pe Network based on the V0.8 API

.DESCRIPTION
Uses V0.8 API, simple response. Used for Renaming networks etc.
Requires the V8 Detailed object to be inserted.
Simply pull the detailed object, make the modifications and sent it back using this API Call.

.PARAMETER PeClusterIP
PeClusterIp is the name or IP for the Prism Element

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER NetworkObj
NetworkObj use REST-Get-PE-Network-V08-Detail to as input.

.EXAMPLE
REST-Update-PE-Network-V08-Obj `
  -PEClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -NetworkObj $SubnetDetail
'19-Sep-21 16:31:37' | INFO  | SET PE Network : 'xxxxxx-115-PaloAlto_Sync2'
'19-Sep-21 16:31:37' | INFO  | SET PE Network : 'd9ef5d91-1499-4aab-9f84-91e61867edcf'

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $NetworkObj
  )

  write-log -message "SET PE Network : '$($NetworkObj.name)'"
  write-log -message "SET PE Network : '$($NetworkObj.uuid)'"

  $NetworkObj.psobject.members.remove("ipConfig") 

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/api/nutanix/v0.8/networks/$($NetworkObj.uuid)"
    Method               = "PUT"
    Headers              = $AuthHeader
    Body                 = $NetworkObj
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Configure DarkSite Proxy for LCM 2.1 
##################################################################

Function REST-Set-Px-Lcm-DarksiteProxy-v21 {
<#
.SYNOPSIS
Sets the Darksite Proxy For LCM V2.1 and lower.

.DESCRIPTION
Uses Legacy Genesis API. Double Escaped Json input format :(
This command is used for the legacy 2.1 LCM API. 
This command has changed at 2.3 and higher.
Still today AOS Ships with 2.1

.PARAMETER PeClusterIP
PeClusterIp is the name or IP for the Prism Element

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER DarkSiteUrl
DarkSiteUrl URL for the Darksite server eg http://xxx/release

.EXAMPLE
REST-Set-Px-Lcm-DarksiteProxy-v21 `
  -PxClusterIP $MainVars.cluster.PeClusterIP `
  -AuthHeader $Mainvars.creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -DarkSiteUrl http://xxx/release

value
-----
{".return": [true, ""]}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $DarkSiteUrl
  )

  $PsHashPayload1 = @{
    ".oid" = "LifeCycleManager"
    ".method" = "lcm_framework_rpc"
    ".kwargs" = @{
      method_class = "LcmFramework"
      method = "configure"
      args = @(
        $DarkSiteUrl
        $true
      )
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Configure DarkSite Proxy for LCM 2.3 
##################################################################

Function REST-Set-Px-Lcm-DarksiteProxy-v23 {
<#
.SYNOPSIS
Sets the Darksite Proxy For LCM V2.3 and Higher.

.DESCRIPTION
Uses Legacy Genesys API. Double Escapped Json input format :(
This command is used for the legacy 2.3 LCM API. 
This command has changed at 2.3 and higher.
Still today AOS Ships with 2.1

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER DarkSiteUrl
DarkSiteUrl URL for the darksite server eg http://xxx/release

.EXAMPLE
REST-Set-Px-Lcm-DarksiteProxy-v23 `
  -PxClusterIP $MainVars.cluster.PeClusterIP `
  -AuthHeader $Mainvars.creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -DarkSiteUrl http://xxx/release

value
-----
{".return": [true, ""]}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $DarkSiteUrl
  )
  $PsHashPayload1 = @{
    ".oid" = "LifeCycleManager"
    ".method" = "lcm_framework_rpc"
    ".kwargs" = @{
      method_class = "LcmFramework"
      method = "configure"
      args = @(
        $DarkSiteUrl
        $true
        "03:00"
        $null
        $null
        $null
        $null
        $true
        $false     
      )
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Create Lcm Build Plan 
##################################################################

Function REST-Create-Pe-Lcm-BuildPlan {
<#
.SYNOPSIS
Creates a build plan for LCM. Requires Updates Object as input, use 1CN-ListUpdates

.DESCRIPTION
Uses Legacy Genesis API. Double Escaped Json input format :(
Creates a build plan for LCM. Use 1CN-List-Px-LCM-Updates

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Updates
Updates Requires Updates Object as input, use 1CN-List-Px-LCM-Updates

.PARAMETER DarkSiteUrl
DarkSiteUrl URL for the Darksite server eg http://xxx/release

.EXAMPLE
REST-Create-Pe-Lcm-BuildPlan `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -Updates $Updates `
  -DarkSiteUrl "$($MainVars.AutoDC.DCxPayloadURL)/$($MainVars.System.DarkSiteLCMPath)"
'14-Nov-21 20:06:38' | INFO  | Constructing Genesis LCM Update Plan Payload.
'14-Nov-21 20:06:38' | INFO  | Adding '3' Updates Inside the Genesis Payload.

value
-----
{".return": {"node:f2bb8cbc-b198-499a-9555-7391628b204b": ["Each node will be rebooted, one node at a time. Except one node cluster, user workloads will not be affected as aut…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $Updates,
    [parameter(mandatory)] [string] $DarkSiteUrl
  )

  write-log -message "Constructing Genesis LCM Update Plan Payload."

  $Count = 0
  $Temp = $null
  $UpdatesArray = $null
  Foreach ($Update in $Updates){
    [Array]$Temp += "DummyChild"
    $Temp[$count] = $($Update.SoftwareUUID, $Update.version)
    $Count ++
  }
  $UpdatesTemp = "Dummy"

  [array]$UpdatesArray += $Temp  

  $PsHashPayload1 = @{
    ".oid" = "LifeCycleManager"
    ".method" = "lcm_framework_rpc"
    ".kwargs" = @{
      method_class = "LcmFramework"
      method = "generate_plan"
      args = @(
        $DarkSiteUrl
        $UpdatesTemp
      )
    }
  }

  write-log -message "Adding '$($Updates.count)' Updates Inside the Genesis Payload."

  $PsHashPayload1.".kwargs".args[1] = $UpdatesArray

  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Install LCM Pe Updates
##################################################################

Function REST-Install-Pe-Lcm-Updates {
<#
.SYNOPSIS
Creates a build plan for LCM. Requires Updates Object as input, use PSR-ListUpdates

.DESCRIPTION
Uses Legacy Genesis API. Double Escaped Json input format :(
Instructs the Prism instance to install Updates.
Prism Element still uses a legacy API

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Updates
Updates Requires Updates Object as input, use 1CN-List-Px-LCM-Updates

.PARAMETER DarkSiteUrl
DarkSiteUrl URL for the Darksite server eg http://xxx/release

.EXAMPLE
REST-Install-Pe-Lcm-Updates `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -Updates $Updates `
  -DarkSiteUrl "$($MainVars.AutoDC.DCxPayloadURL)/$($MainVars.System.DarkSiteLCMPath)"
'14-Nov-21 20:07:30' | INFO  | Constructing Genesis LCM Install Payload.
'14-Nov-21 20:07:30' | INFO  | Adding '3' Updates Inside the Genesis Payload.

value
-----
{".return": "f5b5831e-8e3c-4117-b82a-e281c6f3a84c"}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $Updates,
    [parameter(mandatory)] [string] $DarkSiteUrl
  )

  write-log -message "Constructing Genesis LCM Install Payload."

  $Count = 0
  $Temp = $null
  $UpdatesArray = $null
  Foreach ($Update in $Updates){
    [Array]$Temp += "DummyChild"
    $Temp[$count] = $($Update.SoftwareUUID, $Update.version)
    $Count ++
  }
  $UpdatesTemp = "Dummy"

  [array]$UpdatesArray += $Temp 

  $PsHashPayload1 = @{
    ".oid" = "LifeCycleManager"
    ".method" = "lcm_framework_rpc"
    ".kwargs" = @{
      method_class = "LcmFramework"
      method = "perform_update"
      args = @(
        $DarkSiteUrl
        $UpdatesTemp
      )
    }
  }

  write-log -message "Adding '$($Updates.count)' Updates Inside the Genesis Payload."

  $PsHashPayload1.".kwargs".args[1] = $UpdatesArray
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }

 return Ps-Invoke-Rest `
   -HashArguments $RequestPayload `
   -name (Get-FunctionName)
}

##################################################################
# Get Px LCM Updates via Group Call
##################################################################

Function REST-Get-Px-LCM-GroupUpdates {
<#
.SYNOPSIS
Pulls Raw Group Object from Prism containing all updates. Prism Element or Central Cluster

.DESCRIPTION
Uses group Filter call to retrieve updates.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-LCM-GroupUpdates `
  -PxClusterIP $PxClusterIP `
  -AuthHeader $AuthHeader
'14-Nov-21 20:09:14' | INFO  | Pulling updates via V3 Group Call.

entity_type           : lcm_available_version_v2
filtered_group_count  : 1
total_entity_count    : 9
filtered_entity_count : 9
group_results         : {@{entity_results=System.Object[]; group_by_column_value=; total_entity_count=9; group_summaries=}}
total_group_count     : 1
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload = @{
    entity_type = "lcm_available_version_v2"
    group_member_count = 500
    group_member_attributes = @(@{
      attribute = "uuid"
    }
    @{
      attribute = "entity_uuid"
    }
    @{
      attribute = "entity_class"
    }
    @{
      attribute = "status"
    }
    @{
      attribute = "version"
    }
    @{
      attribute = "dependencies"
    }
    @{
      attribute = "single_group_uuid"
    }
    @{
      attribute = "_master_cluster_uuid_"
    }
    @{
      attribute = "order"
    })
    query_name = "lcm:VersionModel"
    filter_criteria = "_master_cluster_uuid_==[no_val]"
  }

  write-log -message "Pulling Available Updates via V3 Group Call."

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/api/nutanix/v3/groups"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Px LCM Updates via Group Call
##################################################################

Function REST-Get-Px-LCM-GroupInstalled {
<#
.SYNOPSIS
Pulls Raw Group Object from Prism containing all Update Versions. Prism Element or Central

.DESCRIPTION
Uses group Filter call to retrieve updates that are currently installed.
The version table shows if the updates are available.
The output is a complex group call. This groupcall is reconstructed in 1CN-List-Px-LCM-Updates

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-LCM-GroupVersions `
  -PxClusterIP $PxClusterIP `
  -AuthHeader $AuthHeader
'14-Nov-21 20:14:46' | INFO  | Pulling updates via V3 Group Call.

entity_type           : lcm_available_version_v2
filtered_group_count  : 1
total_entity_count    : 9
filtered_entity_count : 9
group_results         : {@{entity_results=System.Object[]; group_by_column_value=; total_entity_count=9; group_summaries=}}
total_group_count     : 1
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  $PsHashPayload = @{
    entity_type = "lcm_entity_v2"
    group_member_count = 500
    group_member_attributes = @(@{
      attribute = "id"
    }
    @{
      attribute = "uuid"
    }
    @{
      attribute = "entity_model"
    }
    @{
      attribute = "version"
    }
    @{
      attribute = "location_id"
    }
    @{
      attribute = "entity_class"
    }
    @{
      attribute = "description"
    }
    @{
      attribute = "last_updated_time_usecs"
    }
    @{
      attribute = "request_version"
    }
    @{
      attribute = "_master_cluster_uuid_"
    }
    @{
      attribute = "entity_type"
    }
    @{
      attribute = "single_group_uuid"
    })
    query_name = "lcm:EntityGroupModel"
    grouping_attribute = "location_id"
    filter_criteria = ""
  }

  write-log -message "Pulling Installed Versions via V3 Group Call."

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/api/nutanix/v3/groups"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Prism Element Network API V 0.8 Detail
##################################################################

Function REST-List-Px-ProgressMonitor {
<#
.SYNOPSIS
Pulls Prism Element or central tasks based on the V1 API

.DESCRIPTION
Universal Task monitor, last 24 hours. Any task UUID can be tracked using this task monitor.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Silent
Does not output anything when set to 1.

.EXAMPLE
REST-List-Px-ProgressMonitor `
  -PxClusterIP $MainVars.cluster.PeClusterIP `
  -AuthHeader $Mainvars.creds.Password_Vault.Site_Pe_Svc.BasicHead
'20-Sep-21 02:02:18' | INFO  | Getting Progress Monitor Tasks
'20-Sep-21 02:02:18' | INFO  | Getting last '24' hours.

metadata
--------
@{grandTotalEntities=8; totalEntities=8; filterCriteria=internal_task==false;(display_failures==[no_val],display_failures==true,(display_failures==false;status!=kFailed));(status==kRunning,complete_time_usecs=gt=1632016938000000);last_updated_time_use…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
                           [Int] $Silent = 1
  )

  if ($Silent -ne 1){
    write-log -message "Getting Progress Monitor Tasks"
  }

  $Date = (Get-date).Addhours(-24)
  $Date = $Date -f "mm/dd/yyyy hh:mm"

  if ($Silent -ne 1){
    write-log -message "Getting last '24' hours." -d 2
  }

  $TotalMilliseconds = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End $Date).TotalMilliseconds
  $TotaluSec = [decimal]$TotalMilliseconds * 1000

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/progress_monitors?hasSubTaskDetail=false&_=$($TotalMilliseconds)&count=500&page=1&filterCriteria=internal_task%3D%3Dfalse%3B(display_failures%3D%3D%5Bno_val%5D%2Cdisplay_failures%3D%3Dtrue%2C(display_failures%3D%3Dfalse%3Bstatus!%3DkFailed))%3B(status%3D%3DkRunning%2Ccomplete_time_usecs%3Dgt%3D$($TotaluSec))%3Blast_updated_time_usecs%3Dgt%3D$($TotaluSec)"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Aos Legacy Upgrade
##################################################################

Function REST-Upgrade-Pe-Aos {
<#
.SYNOPSIS
Upgrades the AOS version using the legacy software update method in the UI.

.DESCRIPTION
Uses Legacy Genesis API. Double Escaped Json input format :(

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER TargetAosVerion
TargetAosVerion Target AOS version for upgrade e.g. 5.20.1.1

.EXAMPLE
REST-Upgrade-Pe-Aos  `
  -PeClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -TargetAosVerion $MainVars.Metadata.AOSVersion.AOSPayloadVersion
'22-Sep-21 22:26:38' | INFO  | Sending Genesis AOS Upgrade call towards '5.20.1.1'

value
-----
{".return": [true, "Successfully committed NOS upgrade intent"]}
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $TargetAosVerion
  )

  write-log -message "Sending Genesis AOS Upgrade call towards '$TargetAosVerion'"

  $PsHashPayload1 = @{
    ".oid" = "ClusterManager"
    ".method" = "cluster_upgrade"
    ".kwargs" = @{
      nos_version = $TargetAosVerion
      manual_upgrade = $false
      ignore_preupgrade_tests = $false
      skip_upgrade = $false
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIP):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Px List Images
##################################################################

Function REST-List-Px-Images {
<#
.SYNOPSIS
List the images regardless of AOS type, works on PC and PE.

.DESCRIPTION
Generic v3 API call. Used in the UI. Lists all the images for this Prism Instance.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Silent
Silent 1, hides any output.

.EXAMPLE
REST-List-Px-Images `
  -PxClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'22-Sep-21 20:26:52' | INFO  | Executing Images List Query

api_version metadata                                             entities
----------- --------                                             --------
3.1         @{total_matches=28; kind=image; length=28; offset=0} {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
                           [string] $Silent = 0
  )

  if ($silent -ne 1){
    write-log -message "Executing Images List Query"
  }

  $PsHashPayload = @{
    kind="image"
    offset=0
    length=9999
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/api/nutanix/v3/images/list"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }
  
  Return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Px Delete Image
##################################################################

Function REST-Delete-Px-Image {
<#
.SYNOPSIS
Deletes an image from the Px Disk Images store.

.DESCRIPTION
Deletes an image from Prism.
V3 API action.
You cannot delete PE images if they are PC managed.

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ImageUuid
Image Uuid of the image :), Pe or Pc.

.EXAMPLE
REST-Delete-Px-Image `
  -PxClusterIP x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead 
  -ImageUuid eeaa5368-0252-460e-9e13-9fad9daf655a
'30-Dec-21 21:13:37' | INFO  | Executing Image Delete action using : 'eeaa5368-0252-460e-9e13-9fad9daf655a'

status                                      spec api_version metadata
------                                      ---- ----------- --------
@{state=DELETE_PENDING; execution_context=}      3.1         @{kind=image}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ImageUuid
  )

  write-log -message "Executing Image Delete action using : '$($ImageUuid)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/api/nutanix/v3/images/$($ImageUuid)"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Px Upload Image
##################################################################

Function REST-Upload-Pe-Image {
<#
.SYNOPSIS
Uploads an image towards Pe Disk Images store.

.DESCRIPTION
V3 API action. Best is to use PE Uploads

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ImageUrl
URL for the image, must include the image filename itself

.PARAMETER ImageName
Prim Name for the image

.PARAMETER ImageContainerUuid
Container UUID for the image

.EXAMPLE
REST-Upload-Pe-Image `
  -PxClusterIP x.x.x.x `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead 
  -ImageUrl http://host/image.qcow2 `
  -ImageName "My Image" `
  -ImageContainerUuid 'eeaa5368-0252-460e-9e13-9fad9daf655a'
'30-Dec-21 21:13:37' | INFO  | Adding Image 'My Image'

status                                      spec api_version metadata
------                                      ---- ----------- --------
@{state=UPLOAD_PENDING; execution_context=}      3.1         @{kind=image}
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ImageUrl,
    [parameter(mandatory)] [string] $ImageName,
    [parameter(mandatory)] [string] $ImageContainerUuid
  )

  Write-Log -message "Adding Image '$ImageName'"

  $ImageType = if (($ImageName -match "ISO" -and $ImageName -notmatch "SO-") -or $ImageUrl -match "ISO") {"ISO_IMAGE"} else {"DISK_IMAGE"}

  $PsHashPayload = @{
    name = "$($ImageName)"
    annotation = "$($ImageName)"
    imageType = "$($ImageType)"
    imageImportSpec = @{
      containerUuid = "$($ImageContainerUuid)"
      url = "$($ImageUrl)"
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/api/nutanix/v0.8/images"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload |convertto-json -depth 5
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Pc mh_vm object
##################################################################

Function REST-Get-Pc-mhvm-detail {
<#
.SYNOPSIS
Pulls the mh_vms object using the Nutanix V3 API

.DESCRIPTION
Hidden API used by the UI to update the categories on a VM. Normal VM update does not work.
mh_vms are used for more than just categories, its a hidden VM API.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER VmUuid
VmUuid UUID of the Virtual Machine

.EXAMPLE
REST-Get-Pc-mhvm-detail `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -VmUuid 7fdfaebb-ae36-48a9-902f-6679222bbbd1
'16-Oct-21 16:23:21' | INFO  | Pulling MH_VMS object for VM '7fdfaebb-ae36-48a9-902f-6679222bbbd1'

api_response_list
-----------------
{@{status=200; api_response=; path_and_params=/api/nutanix/v3/mh_vms/7fdfaebb-ae36-48a9-902f-6679222bbbd1}}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VmUuid
  )

  Write-Log -message "Pulling MH_VMS object for VM '$VmUuid'"

  $ImageType = if ($ImageName -match "ISO" -or $ImageUrl -match "ISO") {"ISO_IMAGE"} else {"DISK_IMAGE"}

  $PsHashPayload = @{
    action_on_failure = "CONTINUE"
    execution_order = "NON_SEQUENTIAL"
    api_request_list = @(@{
      operation = "GET"
      path_and_params = "/api/nutanix/v3/mh_vms/$VMUUID"
    })
    api_version = "3.0"
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/batch"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload |convertto-json -depth 5
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Update Pc mh_vm object
##################################################################

Function REST-Update-Pc-mhvm-object {
<#
.SYNOPSIS
Updates the mh_vms object using the Nutanix V3 API

.DESCRIPTION
Hidden API used by the UI to update the categories on a VM. Normal VM update does not work
mh_vms are used for more than just categories, its a hidden VM API.
Uses a batch call to send the update payload.
The API does not error when the wrong payload is sent inside. 

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER mh_vm_obj
mh_vm_obj use REST-Get-Pc-mhvm-detail to retrieve (api_response_list[0].api_response)

.EXAMPLE
REST-Update-Pc-mhvm-object `
  -PcClusterIp 1.1.1.1 `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead 
  -mh_vm_obj $Mhobj.api_response_list[0].api_response

'30-Dec-21 21:21:07' | INFO  | Updating MH_VMS object for VM 'ef043bf8-464c-4d00-8646-d2f3c9ed8f89'

api_response_list
-----------------
{@{status=202; api_response=; path_and_params=/api/nutanix/v3/mh_vms/ef043bf8-464c-4d00-8646-d2f3c9ed8f89}}

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $mh_vm_obj
  )

  $mh_vm_obj.psobject.members.Remove("status")

  Write-Log -message "Updating MH_VMS object for VM '$($mh_vm_obj.metadata.uuid)'"

  $ImageType = if ($ImageName -match "ISO" -or $ImageUrl -match "ISO") {"ISO_IMAGE"} else {"DISK_IMAGE"}

  $PsHashPayload = @{
    action_on_failure = "CONTINUE"
    execution_order = "NON_SEQUENTIAL"
    api_request_list = @(@{
      operation = "PUT"
      path_and_params = "/api/nutanix/v3/mh_vms/$($mh_vm_obj.metadata.uuid)"
      body = $mh_vm_obj
    })
    api_version = "3.0"
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/batch"
    Method               = "PUT"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload |convertto-json -depth 99
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Px Get Versions
##################################################################

Function REST-Get-Px-Versions {
<#
.SYNOPSIS
Retrieves the AOS version from PC or PE. Keep in mind that this returns the AOS version mapping of PC also, not the actual PC Client facing nr.

.DESCRIPTION
V1 API action. 

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-Versions `
  -PxClusterIP $MainVars.cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead

'17-Oct-21 16:30:04' | INFO  | Pulling AOS Versions from '10.230.88.26'

buildName      : el7.3-release-euphrates-5.20.0.1-stable-f5e54bf50b9b92d1e27560e422629e322968a3e0
buildType      : release
version        : euphrates-5.20.0.1-stable
commitId       : f5e54bf50b9b92d1e27560e422629e322968a3e0
commitIdShort  : f5e54b
lastCommitDate : 2021-06-07 03:52:18 +0000
nccVersion     : 4.2.0.2
isLTS          : True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Pulling AOS Versions from '$PxClusterIP'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/version"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Px Get Image Size
##################################################################

Function REST-Get-Px-Image-Size {
<#
.SYNOPSIS
Uses the Prism Image repository to pull all images, including their size, required / used for ISO mounting

.DESCRIPTION
V0.8 API action. 

.PARAMETER PxClusterIP
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Silent
Silent suppresses the output.

.EXAMPLE
REST-Get-Px-Image-Size `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PxClusterIP $MainVars.Cluster.PeClusterIp `
  -Silent 1

metadata                                 entities
--------                                 --------
@{grandTotalEntities=8; totalEntities=8} {@{uuid=e5920ef4-6b7f-4c60-a0d2-706f87e026df; name=WitnesDisk1; deleted=False; containerId=468; containerUuid=dcf6e446-4068-41ac-8b32-6823d1eed06a; logicalTimestamp=1; imageType=DISK_IMAGE; vmDiskId=cefec377-b3…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [int]    $Silent
  )

  if ($Silent -ne 1) {
    write-log -message "Executing Images List Query With Size"
  }

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/api/nutanix/v0.8/images?includeVmDiskSizes=true"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Get Remote Sites 
##################################################################

Function REST-Get-Pe-Remote-Sites {
<#
.SYNOPSIS
Retrieves all remote sites from prism element

.DESCRIPTION
V1 API action. 

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-PE-Remote-Sites `
  -PeClusterIP $MainVars.Cluster.PEClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead

'26-Oct-21 09:13:12' | INFO  | Pulling remote sites from '10sadsd6'

name                                 : RS_REasdsadC000
uuid                                 : 0005ba33-a0b7-8458-0548-48df37c60a60
remoteIpPorts                        : @{1sadsda15=2020}
remoteIpAddressPorts                 : @sadds7.15=2020}
cloudType                            :
proxyEnabled                         : False
compressionEnabled                   : True
sshEnabled                           : False
vstoreNameMap                        : @{SelfServiceContainer=SelfServiceContainer}
maxBps                               : 1250000
clusterArch                          : X86_64
markedForRemoval                     : False
clusterId                            : 380634292063439456
clusterIncarnationId                 : 1612105786033240
replicationLinks                     : 
capabilities                         : {BACKUP, SUPPORT_DEDUPED_EXTENTS, SUPPORT_KVM}
status                               :
latencyInUsecs                       :
remoteVStoreInfo                     :
metroReady                           : False
bandwidthPolicy                      : @{policyUuid=e34808f4-f2ac-4b82-b4fb-f53381e367ce; policyName=RS_RETasdsda000_BW_Policy; bandwidthConfigurations=System.Object[]; defaultBandwidthLimit=11250000}
bandwidthPolicyEnabled               : True
stats                                : 
networkMapping                       : @{uuid=0a7c7d1d-8fc0-4d72-bb6e-49e25e49dd7a; l2NetworkMappings=System.Object[]}
clusterExternalDataServicesIPAddress : 123
clusterExternalDataServicesAddress   : @{ipv4=1123}
remoteDrExternalSubnet               :
remoteDrExternalSubnetAddress        :
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Pulling remote sites from '$PeClusterIp'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/remote_sites"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Prx Get Remote Sites 
##################################################################

Function REST-Get-Prx-Remote-Sites {
<#
.SYNOPSIS
Retrieves all remote sites from prism element

.DESCRIPTION
V1 API action. 

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Cluster Uuid of the target cluster to run the proxy command.

.EXAMPLE
REST-Get-Prx-Remote-Sites `
  -PeClusterIP $MainVars.Cluster.PEClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead

'26-Oct-21 09:13:12' | INFO  | Pulling remote sites from '10sadsd6'

name                                 : RS_REasdsadC000
uuid                                 : 0005ba33-a0b7-8458-0548-48df37c60a60
remoteIpPorts                        : @{1sadsda15=2020}
remoteIpAddressPorts                 : @sadds7.15=2020}
cloudType                            :
proxyEnabled                         : False
compressionEnabled                   : True
sshEnabled                           : False
vstoreNameMap                        : @{SelfServiceContainer=SelfServiceContainer}
maxBps                               : 1250000
clusterArch                          : X86_64
markedForRemoval                     : False
clusterId                            : 380634292063439456
clusterIncarnationId                 : 1612105786033240
replicationLinks                     : 
capabilities                         : {BACKUP, SUPPORT_DEDUPED_EXTENTS, SUPPORT_KVM}
status                               :
latencyInUsecs                       :
remoteVStoreInfo                     :
metroReady                           : False
bandwidthPolicy                      : @{policyUuid=e34808f4-f2ac-4b82-b4fb-f53381e367ce; policyName=RS_RETasdsda000_BW_Policy; bandwidthConfigurations=System.Object[]; defaultBandwidthLimit=11250000}
bandwidthPolicyEnabled               : True
stats                                : 
networkMapping                       : @{uuid=0a7c7d1d-8fc0-4d72-bb6e-49e25e49dd7a; l2NetworkMappings=System.Object[]}
clusterExternalDataServicesIPAddress : 123
clusterExternalDataServicesAddress   : @{ipv4=1123}
remoteDrExternalSubnet               :
remoteDrExternalSubnetAddress        :
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid
  )

  write-log -message "Pulling PE Remote Sites using PC Proxy, Cluster target '$($ClusterUuid)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/remote_sites?proxyClusterUuid=$($ClusterUuid)"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Delete Pe Protection Domain Snap Shots 
##################################################################

Function REST-Delete-Pe-ProtectionDomain-Single-Snapshots {
<#
.SYNOPSIS
Deletes a single snapshot from a PD. 

.DESCRIPTION
V1 API action. Snapshots inside a PD are considered local at all times, remote IDs are the same as local IDs except exist in a different location.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
Name of the protection domain.

.PARAMETER SnapId
ID of the snapshot, integer

.EXAMPLE
REST-Delete-Pe-ProtectionDomain-Single-RemoteSnapshots `
  -PeClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -SnapId 4035377  `
  -PdName xxxxx-Gold_CCG
'13-Nov-21 01:31:51' | INFO  | Deleting Snap : '4035377' out of Protecion Domain : 'xxx-Gold_CCG'

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName,
    [parameter(mandatory)] [INT]    $SnapId
  )

  write-log -message "Deleting Snap : '$SnapId' out of Protecion Domain : '$PdName'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)/dr_snapshots/$SnapID"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Delete Pe Protection Domain Snap Shot List
##################################################################

Function REST-Delete-Pe-ProtectionDomain-List-Snapshots {
<#
.SYNOPSIS
Deletes a single snapshot from a PD. 

.DESCRIPTION
V1 API action. Snapshots inside a PD are considered local at all times, remote IDs are the same as local IDs except exist in a different location.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
Name of the protection domain.

.PARAMETER SnapList
Array of IDs that should be deleted.

.PARAMETER RemoteSiteName
Name of the remote site.  

.EXAMPLE

#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName,
    [parameter(mandatory)] [Array]  $SnapList,
    [parameter(mandatory)] [string] $RemoteSiteName
  )

  $PsHashPayload = @{
    drSnapshotIdsMap= @{
      "$($PdName)"  =@(
        $SnapList
      )
    }
  }

  write-log -message "Deleting Snap : '$SnapId' out of Protecion Domain : '$PdName'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/remote_sites/$($RemoteSiteName)/dr_snapshots/remove_list"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Get Protection Domain Snapshots 
##################################################################

Function REST-Get-Pe-ProtectionDomain-Snapshots {
<#
.SYNOPSIS
Retrieves all local snapshots from a protection domain

.DESCRIPTION
V1 API action. 

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
Name of the protection domain.

.EXAMPLE
REST-Get-Pe-ProtectionDomain-Snapshots `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PdName xxxx-NXC000-Gold_CCG
'14-Nov-21 09:35:24' | INFO  | Pulling Snaps out of Protecion Domain : 'xxx4-NXC000-Gold_CCG'

metadata                                                                                 entities
--------                                                                                 --------
@{grandTotalEntities=59; totalEntities=59; filterCriteria=state!=EXPIRED; sortCriteria=} {@{protectionDomainName=xxxxx
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName
  )

  write-log -message "Pulling Snaps out of Protecion Domain : '$PdName'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)/dr_snapshots?fullDetails=true&projection=stats%2Calerts&filterCriteria=state!%3DEXPIRED"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Get Remote Site Snapshots 
##################################################################

Function REST-Get-Pe-RemoteSite-Snapshots {
<#
.SYNOPSIS
Retrieves all local snapshots from a Remote Site

.DESCRIPTION
V1 API action. 

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER RemoteSiteName 
RemoteSiteName the name of the Remote Site

  .EXAMPLE
REST-Get-Pe-RemoteSite-Snapshots `
  -PEClusterIP $MainVars.Cluster.PEClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -RemoteSiteName RS_xxx-NXC000
'14-Nov-21 09:40:58' | INFO  | Pulling Snaps out of Remote Site : 'RS_xx-NXC000'

metadata                                                                               entities
--------                                                                               --------
@{grandTotalEntities=2; totalEntities=2; filterCriteria=state!=EXPIRED; sortCriteria=} {@{protectionDomainName=Rxx…
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $RemoteSiteName
  )

  write-log -message "Pulling Snaps out of Remote Site : '$RemoteSiteName'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/remote_sites/$($RemoteSiteName)/dr_snapshots?fullDetails=true&projection=stats%2Calerts&filterCriteria=state!%3DEXPIRED"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Prx Get Pe License
##################################################################

Function REST-Get-Prx-License {
<#
.SYNOPSIS
Retrieves Nutanix Licenses for the PE Specified in the ProxyCluster Uuid

.DESCRIPTION
V1 API action. 

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Cluster Uuid the uuid of the cluster to proxy towards

.EXAMPLE
REST-Get-Pe-RemoteSite-Snapshots `
  -PEClusterIP $MainVars.Cluster.PEClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -RemoteSiteName RS_xxx-NXC000
'14-Nov-21 09:40:58' | INFO  | Pulling Snaps out of Remote Site : 'RS_xx-NXC000'

metadata                                                                               entities
--------                                                                               --------
@{grandTotalEntities=2; totalEntities=2; filterCriteria=state!=EXPIRED; sortCriteria=} {@{protectionDomainName=Rxx…

  #>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $ClusterUuid
  )

  write-log -message "Getting PE Remote Site License using PC Proxy '$($ClusterUUID)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/license?proxyClusterUuid=$($ClusterUUID)"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Prx Get Remote Site Detail
##################################################################

Function REST-Get-Prx-RemoteSite-Detail {
<#
.SYNOPSIS
Retrieves Detailed Remote Site Object for the PE Specified in the ProxyCluster Uuid

.DESCRIPTION
V1 API action. 

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Cluster Uuid the uuid of the cluster to proxy towards

.PARAMETER SiteName
Name of the remote site.

.EXAMPLE
REST-Get-Prx-RemoteSite-Detail `
  -PcClusterIp $MainVars.AutoDc.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ClusterUUID 0005ba33-a0b7-8458-0548-48df37c60a60 `
  -SiteName $RsName
'14-Nov-21 09:57:41' | INFO  | Getting PE Remote Sites using PC Proxy, Cluster target '0005ba33-a0b7-8458-0548-48df37c60a60' with sitename 'xxxxxx-NXC000'

name                                 : RS_xxxxx
uuid                                 : 0005aa62-797b-1f9a-6c01-48df37c63270
remoteIpPorts                        : @{xxxxx}
remoteIpAddressPorts                 : @{1.1.1.1=2020}
cloudType                            :
proxyEnabled                         : False
compressionEnabled                   : True
sshEnabled                           : False
vstoreNameMap                        : @{SelfServiceContainer=SelfServiceContainer}
maxBps                               : 1250000
clusterArch                          : X86_64
markedForRemoval                     : False
clusterId                            : 7782581754623570544
clusterIncarnationId                 : 1594714805182362
replicationLinks                     : {}
capabilities                         : {BACKUP, SUPPORT_DEDUPED_EXTENTS, SUPPORT_KVM}
status                               :
latencyInUsecs                       :
remoteVStoreInfo                     :
metroReady                           : False
bandwidthPolicy                      : @{policyUuid=3ec74157-a75d-46f0-9b11-631954957f6c; policyName=xxxxxx-NXC000_BW_Policy; bandwidthConfigurations=System.Object[]; defaultBandwidthLimit=11250000}
bandwidthPolicyEnabled               : True
stats                                : @{hypervisor_avg_io_latency_usecs=-1; num_read_iops=-1; hypervisor_write_io_bandwidth_kBps=-1; timespan_usecs=-1; controller_num_read_iops=-1; read_io_ppm=-1; controller_num_iops=-1; total_read_io_time_usecs=-1;
                                       controller_total_read_io_time_usecs=0; replication_transmitted_bandwidth_kBps=0; hypervisor_num_io=-1; controller_total_transformed_usage_bytes=-1; controller_num_write_io=-1; avg_read_io_latency_usecs=-1;
                                       controller_total_io_time_usecs=0; controller_total_read_io_size_kbytes=0; controller_num_seq_io=-1; controller_read_io_ppm=-1; controller_total_io_size_kbytes=0; controller_num_io=0;
                                       hypervisor_avg_read_io_latency_usecs=-1; num_write_iops=-1; controller_num_random_io=0; num_iops=-1; replication_received_bandwidth_kBps=0; hypervisor_num_read_io=-1; hypervisor_total_read_io_time_usecs=-1;
                                       controller_avg_io_latency_usecs=-1; num_io=-1; controller_num_read_io=0; hypervisor_num_write_io=-1; controller_seq_io_ppm=-1; controller_read_io_bandwidth_kBps=-1; controller_io_bandwidth_kBps=-1;
                                       hypervisor_timespan_usecs=-1; hypervisor_num_write_iops=-1; replication_num_transmitted_bytes=0; total_read_io_size_kbytes=-1; hypervisor_total_io_size_kbytes=-1; avg_io_latency_usecs=-1;
                                       hypervisor_num_read_iops=-1; controller_write_io_bandwidth_kBps=-1; controller_write_io_ppm=-1; hypervisor_avg_write_io_latency_usecs=-1; hypervisor_total_read_io_size_kbytes=-1; read_io_bandwidth_kBps=-1;
                                       hypervisor_num_iops=-1; hypervisor_io_bandwidth_kBps=-1; controller_num_write_iops=-1; total_io_time_usecs=-1; controller_random_io_ppm=-1; controller_avg_read_io_size_kbytes=-1; total_transformed_usage_bytes=-1;
                                       avg_write_io_latency_usecs=-1; num_read_io=-1; write_io_bandwidth_kBps=-1; hypervisor_read_io_bandwidth_kBps=-1; random_io_ppm=-1; total_untransformed_usage_bytes=-1; hypervisor_total_io_time_usecs=-1;
                                       num_random_io=-1; controller_avg_write_io_size_kbytes=-1; controller_avg_read_io_latency_usecs=-1; num_write_io=-1; total_io_size_kbytes=-1; io_bandwidth_kBps=-1; replication_num_received_bytes=0;
                                       controller_timespan_usecs=0; num_seq_io=-1; seq_io_ppm=-1; write_io_ppm=-1; controller_avg_write_io_latency_usecs=-1}
networkMapping                       : @{uuid=77b8b33b-3fc0-43ee-b285-e837428562f4; l2NetworkMappings=System.Object[]}
clusterExternalDataServicesIPAddress : xxxxx
clusterExternalDataServicesAddress   : @{ipv4=xxxxx}
remoteDrExternalSubnet               :
remoteDrExternalSubnetAddress        :
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid,
                                    $SiteName
  )

  write-log -message "Getting PE Remote Sites using PC Proxy, Cluster target '$($ClusterUuid)' with sitename '$SiteName'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/remote_sites/$($SiteName)?proxyClusterUuid=$($ClusterUuid)"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Prx Update Remote Site
##################################################################

Function REST-Update-Prx-RemoteSite {
<#
.SYNOPSIS
Updates the entire remote site object, using the pc Proxy url construct.

.DESCRIPTION
V1 API action. 

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Cluster Uuid the uuid of the cluster to proxy towards

.PARAMETER TargetIp
TargetIp Remote site Target IP, typically the Pe Cluster IP of the target cluster.

.PARAMETER BwPolicyStart  
BwPolicyStart Start time in unix time for bandwidth cap start of Daytime

.PARAMETER BwPolicyEnd 
BwPolicyEnd End time in unix time for bandwidth cap end of Daytime

.PARAMETER BwCapDay
Bandwidth limit during the policy active time, hence referred to as the daytime bandwidth cap.

.PARAMETER BwCapNight
Bandwidth limit outside the policy active time, hence referred to as the night time bandwidth cap.

.PARAMETER NwMapObj 
NwMapObj network mapping object. use REST-Get-Prx-Networks

.PARAMETER RemoteSiteObj 
RemoteSiteObj Remote Site Object (Use REST-Get-Prx-RemoteSite-Detail as input.)

.PARAMETER EnableCompression
Boolean to enable inline compression on the traffic.

.PARAMETER Exists
Assumed false, if exists, the network mapping is not updated.

.EXAMPLE
REST-Update-Prx-RemoteSite `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ClusterUuid $ReplicationSource.metadata.uuid `
  -TargetIp $ReplicationTarget.spec.resources.network.external_Ip `
  -BwPolicyStart $ReplPolicystart `
  -BwPolicyEnd $ReplPolicyEnd `
  -BwCapDay $daytimeBandwidth_Bps `
  -BwCapNight $nighttimeBandwidth_Bps `
  -NwMapObj $SourceMappings `
  -RemoteSiteObj $SiteDetail `
  -EnableCompression $Compression
'14-Nov-21 10:38:31' | INFO  | Updating Remote Site through PC Proxy, Cluster target '0005ba33-a0b7-8458-0548-48df37c60a60'
'14-Nov-21 10:38:31' | INFO  | Adding a bandwidthPolicy
'14-Nov-21 10:38:31' | INFO  | One schedule will do for this timezone...
'14-Nov-21 10:38:31' | INFO  | Setting Compression state: 'False'
'14-Nov-21 10:38:31' | INFO  | Mapping DataStores, SSP only, hardcoded.
'14-Nov-21 10:38:31' | INFO  | Looping through Mappings
'14-Nov-21 10:38:31' | INFO  | We have '2' Network mappings to add

name                                 : RS_xxxx
uuid                                 : 0005aa62-797b-1f9a-6c01-48df37c63270
remoteIpPorts                        : @{1.1.1.1=2020}
remoteIpAddressPorts                 : @{1.1.1.1=2020}
cloudType                            :
proxyEnabled                         : False
compressionEnabled                   : False
sshEnabled                           : False
vstoreNameMap                        : @{SelfServiceContainer=SelfServiceContainer}
maxBps                               : 1250000
clusterArch                          : X86_64
markedForRemoval                     : False
clusterId                            : 7782581754623570544
clusterIncarnationId                 : 1594714805182362
replicationLinks                     : {}
capabilities                         : {BACKUP, SUPPORT_DEDUPED_EXTENTS, SUPPORT_KVM}
status                               : relationship established
latencyInUsecs                       :
remoteVStoreInfo                     : @{default-container-69271760109880=; SelfServiceContainer=; NutanixManagementShare=}
metroReady                           : True
bandwidthPolicy                      : @{policyUuid=ada31dfa-c94a-4ce5-b5d7-3d81ddbe0497; policyName=xxxxx-NXC000_Bw_Policy; bandwidthConfigurations=System.Object[]; defaultBandwidthLimit=11250000}
bandwidthPolicyEnabled               : True
networkMapping                       : @{uuid=ebd6bf83-97b2-4814-8d52-5e2d0badbf08; l2NetworkMappings=System.Object[]}
clusterExternalDataServicesIPAddress : 1.1.1.1
clusterExternalDataServicesAddress   : @{ipv4=1.1.1.1}
remoteDrExternalSubnet               :
remoteDrExternalSubnetAddress        :
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid,
    [parameter(mandatory)] [string] $TargetIp,
    [parameter(mandatory)] [long]   $BwPolicyStart,
    [parameter(mandatory)] [long]   $BwPolicyEnd,
    [parameter(mandatory)] [string] $BwCapDay,
    [parameter(mandatory)] [string] $BwCapNight,
                           [object] $NwMapObj,
    [parameter(mandatory)] [object] $RemoteSiteObj,
                           [Bool]   $EnableCompression = $true,
                           [Bool]   $Exists = $False
  )

  write-log -message "Updating Remote Site through PC Proxy, Cluster target '$($ClusterUuid)'"

  if ($RemoteSiteObj.psobject.members.name -contains "stats"){
    $RemoteSiteObj.psobject.members.Remove("stats")

    write-log -message "Removing Stats"

  }
  if ([array]$RemoteSiteObj.replicationLinks.count -ge 1){
    
    $RemoteSiteObj.replicationLinks | % { 

      $_.psobject.members.Remove("stats")

      write-log -message "Removing Replication Link Stats"

    }
  }
  write-log -message "Adding a bandwidthPolicy"

  if ($BwPolicyEnd -le $BwPolicyStart){

    write-log "This schedule is cross midnight. Lets add 2 schedules.."

    $BwPolObj = @{
      policyName = "$($RemoteSiteObj.name)_Bw_Policy"
      bandwidthConfigurations = @(@{
        startTime = $BwPolicyStart
        endTime = 86340000000
        daysSelected = 127
        bandwidthLimit = $BwCapDay
      }
      @{
        startTime = 0
        endTime = $BwPolicyEnd
        daysSelected = 127
        bandwidthLimit = $BwCapDay
      })
      defaultBandwidthLimit = $BwCapNight
    }

  } else {

    write-log "One schedule will do for this timezone..."

    $BwPolObj = @{
      policyName = "$($RemoteSiteObj.name)_Bw_Policy"
      bandwidthConfigurations = @(@{
        startTime = $BwPolicyStart
        endTime = $BwPolicyEnd
        daysSelected = 127
        bandwidthLimit = $BwCapDay
      })
      defaultBandwidthLimit = $BwCapNight
    }
  } 

  $RemoteSiteObj.psobject.members.Remove("bandwidthPolicy")
  $RemoteSiteObj | add-member bandwidthPolicy $BwPolObj
  $RemoteSiteObj.bandwidthPolicyEnabled = $true

  write-log -message "Setting Compression state: '$EnableCompression'"

  $RemoteSiteObj.compressionEnabled = $EnableCompression

  write-log -message "Mapping DataStores, SSP only, hardcoded."

  $VStoreNameMap = @{
    SelfServiceContainer = "SelfServiceContainer"
  }
  $RemoteSiteObj.vstoreNameMap = $VStoreNameMap

  [array]$NWMapObjects = $null

  write-log -message "Looping through Mappings"

  foreach ($Mapping in $NwMapObj){
    $NwMapHash = @{
      srcHypervisorType   = "kKvm"
      srcNetworkName      = "$($Mapping.Source)"
      destHypervisorType  = "kKvm"
      destNetworkName     = "$($Mapping.Target)"
    }
    [Array]$NwMapObjectArr += $NwMapHash 
  }

  $NetworkMapping = @{
    UUID              = $null
    l2NetworkMappings = $NwMapObjectArr
  }

  if (!$Exists){

    write-log -message "We have '$($NwMapObjectArr.count)' Network mappings to add"

    $RemoteSiteObj.networkMapping = $NetworkMapping

  } else {

    write-log -message "Network mappings cannot be changed when already used."

  }
  
  write-log -message "Updating Remote Site: '$($RemoteSiteObj.name)'"

  if (get-childitem c:\temp\ -ea:4){
    $RemoteSiteObj | convertto-json -depth 100 | out-file "c:\temp\RemoteSiteObj-$($RemoteSiteObj.name).json"
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/remote_sites?proxyClusterUuid=$($ClusterUuid)"
    Method               = "PUT"
    Body                 = $RemoteSiteObj
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Create Protection Domain
##################################################################

Function REST-Create-Pe-ProtectionDomain {
<#
.SYNOPSIS
Creates an Empty Protection Domain

.DESCRIPTION
Creates a Prism Element based protection domain. These PDs are independent from Prism Central.
Ideal use for distributed clusters.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
PdName the name of the Protection Domain

.EXAMPLE
REST-Create-Pe-ProtectionDomain `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PdName "BPAutonomics"
'14-Nov-21 10:55:00' | INFO  | Creating Protection Domain

name                    : BPAutonomics
vms                     : {}
nfsFiles                : {}
volumeGroups            : {}
vstoreId                :
active                  : True
remoteSiteNames         : {}
cronSchedules           : {}
minSnapshotToRetain     :
nextSnapshotTimeUsecs   :
pendingReplicationCount : 0
ongoingReplicationCount : 0
markedForRemoval        : False
hybridSchedulesCount    :
metroAvail              :
totalUserWrittenBytes   :
replicationLinks        : {}
syncReplications        :
annotations             : {}
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName
  )
  write-log -message "Creating Protection Domain"

  $PsHashPayload = @{
    value = $PdName
  }

  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Add Protection Domain Vms
##################################################################

Function REST-Add-Pe-ProtectionDomain-Vms {
<#
.SYNOPSIS
Sets the protected Vms to existing Protection Domain.

.DESCRIPTION
Works as addition. You cannot add Vms that are apart of a different PD, use REST-Remove-Pe-ProtectionDomain-Vms to remove

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
PdName the name of the Protection Domain

.PARAMETER VmIds
VmIds array of VM Ids, this is not the VM UUID, but the VM ID 

.PARAMETER Acg
Boolean, when set to true, makes sure application consistent snaps are taken.

.EXAMPLE
REST-Add-Pe-ProtectionDomain-Vms `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PdName $PdName `
  -VmIds $VmVmIdArr `
  -Acg $Acg
'14-Nov-21 11:16:12' | INFO  | Adding Protection Domain Entities

name                    : Rxxxx-NXC000-Gold_CCG
vms                     : {@{vmHandle=5264050; vmId=775e48ff-d9e7-4cf9-a086-5e4a4b5fa9cf; vmName=xxxx-WS0001; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=xxxxx-WS0001; appConsistentSnapshots=False;
                          vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}, @{vmHandle=7595955; vmId=a28b1e8b-7531-4882-93a5-a4cf7d6ab1f2; vmName=xxxxx-NT4903; vmPowerStateOnRecovery=Power state at time of snapshot;
                          consistencyGroup=xxxx-NT4903; appConsistentSnapshots=False; vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}, @{vmHandle=7595951; vmId=5f183e7f-7ed9-4815-a5f1-a7aa25a013ec;
                          vmName=xxxxx-LC0001; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=xxxx-LC0001; appConsistentSnapshots=False; vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]},
                          @{vmHandle=5264058; vmId=74d9f9f6-6d41-42aa-bf4e-9a7095868802; vmName=xxx-NT8050; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=xxxx-NT8050; appConsistentSnapshots=False;
                          vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}…}
nfsFiles                : {}
volumeGroups            : {}
vstoreId                :
active                  : True
remoteSiteNames         : {RS_xxxx-NXC000}
cronSchedules           : {@{suspended=False; pdName=Rxxx-NXC000-Gold_CCG; id=0855b5d2-cd7d-40cf-9594-23865d91e403; type=HOURLY; values=; everyNth=2; userStartTimeInUsecs=16368143240; startTimesInUsecs=System.Object[]; endTimeInUsecs=;
                          retentionPolicy=; appConsistent=False; rollupScheduleUuid=; isRollupSched=}, @{suspended=False; pdName=xxxxx-NXC000-Gold_CCG; id=01cbd729-cb77-4868-b7cc-42501e1814d7; type=DAILY; values=; everyNth=1;
                          userStartTimeInUsecs=16368143240; startTimesInUsecs=System.Object[]; endTimeInUsecs=; retentionPolicy=; appConsistent=False; rollupScheduleUuid=; isRollupSched=}}
minSnapshotToRetain     :
schedulesSuspended      : False
nextSnapshotTimeUsecs   : 1636885968143000
pendingReplicationCount : 0
ongoingReplicationCount : 0
markedForRemoval        : False
hybridSchedulesCount    : 0
metroAvail              :
totalUserWrittenBytes   :
replicationLinks        : {@{id=(xxxx-NXC000-Gold_CCG,RS_PTSEELM-NXC000); protectionDomainName=xxxxxx-NXC000-Gold_CCG; remoteSiteName=RS_PTSEELM-NXC000; currentReplicatingSnapshotId=7578869; currentReplicatingSnapshotTotalBytes=7741933056;
                          currentReplicatingSnapshotTransmittedBytes=3061554419; lastSuccessfulReplicationSnapshotId=7578869; lastReplicationStartTimeInUsecs=1636345950391501; lastReplicationEndTimeInUsecs=1636346268736096; stats=}}
syncReplications        :
annotations             : {}
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName,
    [parameter(mandatory)] [array]  $VmIds,
                           [Bool]   $Acg = $false
  )
  
  write-log -message "Adding Protection Domain Entities"

  $PsHashPayload= @{
    vmAddRemoveType = "LISTED_VMS"
    protectionDomainName = $PdName
    vmIds = @()
    volumeGroupUuids = @()
    appConsistentSnapshots = $Acg
    protectRelatedEntities = $true
  } 

  $PsHashPayload.VmIds += $VmIds
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)/add_entities"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Remove Protection Domain Vms
##################################################################

Function REST-Remove-Pe-ProtectionDomain-Vms {
<#
.SYNOPSIS
Removes Vms from existing Protection Domain.

.DESCRIPTION
Works as removal.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
PdName the name of the Protection Domain

.PARAMETER VmIds
VmIds array of VM Ids, this is not the VM UUID, but the VM ID

  .EXAMPLE
REST-Remove-Pe-ProtectionDomain-Vms `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PdName $PdName `
  -VmIds $VmVmIdArr
'14-Nov-21 12:38:09' | INFO  | Adding Protection Domain Entities

name                    : xxxx-NXC000-Gold_CCG
vms                     : {@{vmHandle=5264050; vmId=775e48ff-d9e7-4cf9-a086-5e4a4b5fa9cf; vmName=xxxx-WS0001; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=xxxx-WS0001; appConsistentSnapshots=False;
                          vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}, @{vmHandle=7595955; vmId=a28b1e8b-7531-4882-93a5-a4cf7d6ab1f2; vmName=xxxx-NT4903; vmPowerStateOnRecovery=Power state at time of snapshot;
                          consistencyGroup=xxxx-NT4903; appConsistentSnapshots=False; vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}, @{vmHandle=7595951; vmId=5f183e7f-7ed9-4815-a5f1-a7aa25a013ec;
                          vmName=xxxx-LC0001; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=xxx-LC0001; appConsistentSnapshots=False; vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]},
                          @{vmHandle=5264058; vmId=74d9f9f6-6d41-42aa-bf4e-9a7095868802; vmName=xxx-NT8050; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=xxxxx-NT8050; appConsistentSnapshots=False;
                          vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}…}
nfsFiles                : {}
volumeGroups            : {}
vstoreId                :
active                  : True
remoteSiteNames         : {RS_xxxxx-NXC000}
cronSchedules           : {@{suspended=False; pdName=xxxx-NXC000-Gold_CCG; id=0855b5d2-cd7d-40cf-9594-23865d91e403; type=HOURLY; values=; everyNth=2; userStartTimeInUsecs=16368143240; startTimesInUsecs=System.Object[]; endTimeInUsecs=;
                          retentionPolicy=; appConsistent=False; rollupScheduleUuid=; isRollupSched=}, @{suspended=False; pdName=xxxxx-NXC000-Gold_CCG; id=01cbd729-cb77-4868-b7cc-42501e1814d7; type=DAILY; values=; everyNth=1;
                          userStartTimeInUsecs=16368143240; startTimesInUsecs=System.Object[]; endTimeInUsecs=; retentionPolicy=; appConsistent=False; rollupScheduleUuid=; isRollupSched=}}
minSnapshotToRetain     :
schedulesSuspended      : False
nextSnapshotTimeUsecs   : 1636893168143000
pendingReplicationCount : 0
ongoingReplicationCount : 0
markedForRemoval        : False
hybridSchedulesCount    : 0
metroAvail              :
totalUserWrittenBytes   :
replicationLinks        : {@{id=(xxxx-NXC000-Gold_CCG,RS_PTSEELM-NXC000); protectionDomainName=xxxxx-NXC000-Gold_CCG; remoteSiteName=RS_PTSEELM-NXC000; currentReplicatingSnapshotId=7578869; currentReplicatingSnapshotTotalBytes=7741933056;
                          currentReplicatingSnapshotTransmittedBytes=3061554419; lastSuccessfulReplicationSnapshotId=7578869; lastReplicationStartTimeInUsecs=1636345950391501; lastReplicationEndTimeInUsecs=1636346268736096; stats=}}
syncReplications        :
annotations             : {}
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName,
    [parameter(mandatory)] [array]  $VmIds
  )
  
  write-log -message "Removing Protection Domain Entities"

  $PsHashPayload= @{
    vmAddRemoveType = "LISTED_VMS"
    protectionDomainName = $PdName
    vmIds = @($VmIds | Where-Object {$_})
    volumeGroupUuids = @()
  } 
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)/remove_entities"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Delete Pe Protection Domain
##################################################################

Function REST-Delete-Pe-ProtectionDomain {
<#
.SYNOPSIS
Deletes a single snapshot from a PD. 

.DESCRIPTION
V1 API action. Snapshots inside a PD are considered local at all times, remote IDs are the same as local IDs except exist in a different location.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
PdName the name of the Protection Domain

.EXAMPLE
PS C:\Program Files\PowerShell\7> REST-Delete-Pe-ProtectionDomain `
>>          -PEClusterIp $MainVars.Cluster.PeClusterIp `
>>          -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
>>          -PdName "BPAutonomics"
'14-Nov-21 12:50:27' | INFO  | Deleting PD with name 'BPAutonomics'

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName
  )

  write-log -message "Deleting PD with name '$($PdName)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Prx Get Remote Site Detail
##################################################################

Function REST-Get-Prx-ProtectionDomain-Pending-Replications {
<#
.SYNOPSIS
Retrieves Detailed Remote Site Object for the PE Specified in the ProxyCluster Uuid

.DESCRIPTION
V1 API action. 

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Uuid of the cluster we proxy this command through.

.PARAMETER PdName
PdName the name of the Protection Domain

.EXAMPLE
REST-Get-Prx-Pending-ProtectionDomain-Replications `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -PdName $Pdname `
  -ClusterUuid $ReplicationCurrentTarget.metadata.uuid
'14-Nov-21 12:57:42' | INFO  | Getting Pending Replications inside PD 'xxxxxxx-NXC000-Gold_CCG' on Cluster '0005aa62-797b-1f9a-6c01-48df37c63270'
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid,
    [parameter(mandatory)] [string] $PdName
  )

  write-log -message "Getting Pending Replications inside PD '$($PdName)' on Cluster '$($ClusterUuid)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/replications?protectionDomainNames=$($PdName)&proxyClusterUuid=$($ClusterUuid)"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  write-log -message $RequestPayload.uri

  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Prx Delete Remote Site Detail
##################################################################

Function REST-Delete-Prx-ProtectionDomain {
<#
.SYNOPSIS
Retrieves Detailed Remote Site Object for the PE Specified in the ProxyCluster Uuid

.DESCRIPTION
V1 API action. 

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Uuid of the cluster we proxy this command through.

.PARAMETER PdName
PdName the name of the Protection Domain

.EXAMPLE
REST-Delete-Prx-ProtectionDomain `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -PdName BPAutonomics `
  -ClusterUuid $clusterUuid
'14-Nov-21 13:11:28' | INFO  | Deleting PD with name 'BPAutonomics' on Cluster '0005ba33-a0b7-8458-0548-48df37c60a60'

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid,
    [parameter(mandatory)] [string] $PdName
  )

  write-log -message "Deleting PD with name '$($PdName)' on Cluster '$($ClusterUUID)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)?proxyClusterUuid=$($ClusterUUID)"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Get Protection Domain
##################################################################

Function REST-Get-Pe-ProtectionDomains {
<#
.SYNOPSIS
Retrieves Detailed Remote Site Object for the PE Specified in the ProxyCluster Uuid

.DESCRIPTION
V1 API action. 

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Uuid of the cluster we proxy this command through.

.PARAMETER PdName
PdName the name of the Protection Domain

.EXAMPLE
REST-Get-Pe-ProtectionDomains `
  -PEClusterIP $MainVars.Cluster.PEClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'14-Nov-21 13:17:49' | INFO  | Retrieving PE Protection Domains.

name                    : xx-NXC000-Gold_CCG
vms                     : {@{vmHandle=5264050; vmId=775e48ff-d9e7-4cf9-a086-5e4a4b5fa9cf; vmName=xxx-WS0001; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=xxx-WS0001; appConsistentSnapshots=False;
                          vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}, @{vmHandle=5264058; vmId=74d9f9f6-6d41-42aa-bf4e-9a7095868802; vmName=xxxxxx-NT8050; vmPowerStateOnRecovery=Power state at time of snapshot;
                          consistencyGroup=xxx-NT8050; appConsistentSnapshots=False; vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}, @{vmHandle=xxxx; vmId=85589358-5219-4422-a503-e49cb7e2e38c;
                          vmName=xxxx-NX4-Move; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=xxxxx-NX4-Move; appConsistentSnapshots=False; vmRecoverability=System.Object[]; vmFiles=;
                          relatedEntityUuids=System.Object[]}, @{vmHandle=5264070; vmId=e865b142-6f9b-4e9c-a4c1-9e565a8cbc2c; vmName=POSSE445-NT8050.; vmPowerStateOnRecovery=Power state at time of snapshot; consistencyGroup=POSSE445-NT8050.;
                          appConsistentSnapshots=False; vmRecoverability=System.Object[]; vmFiles=; relatedEntityUuids=System.Object[]}…}
nfsFiles                : {}
volumeGroups            : {}
vstoreId                :
active                  : True
remoteSiteNames         : {RS_xxxx-NXC000}
cronSchedules           : {@{suspended=False; pdName=xxxx-NXC000-Gold_CCG; id=0855b5d2-cd7d-40cf-9594-23865d91e403; type=HOURLY; values=; everyNth=2; userStartTimeInUsecs=16368143240; startTimesInUsecs=System.Object[]; endTimeInUsecs=;
                          retentionPolicy=; appConsistent=False; rollupScheduleUuid=; isRollupSched=}, @{suspended=False; pdName=xxx-NXC000-Gold_CCG; id=01cbd729-cb77-4868-b7cc-42501e1814d7; type=DAILY; values=; everyNth=1;
                          userStartTimeInUsecs=16368143240; startTimesInUsecs=System.Object[]; endTimeInUsecs=; xxx=; appConsistent=False; rollupScheduleUuid=; isRollupSched=}}
minSnapshotToRetain     :
schedulesSuspended      : False
nextSnapshotTimeUsecs   : 1636893168000000
pendingReplicationCount : 0
ongoingReplicationCount : 0
markedForRemoval        : False
hybridSchedulesCount    : 0
metroAvail              :
totalUserWrittenBytes   : 434222628864
replicationLinks        : {@{id=(xxxxx-NXC000-Gold_CCG,RS_PTSEELM-NXC000); protectionDomainName=xxxx-NXC000-Gold_CCG; remoteSiteName=RS_PTSEELM-NXC000; currentReplicatingSnapshotId=7578869; currentReplicatingSnapshotTotalBytes=7741933056;
                          currentReplicatingSnapshotTransmittedBytes=3061554419; lastSuccessfulReplicationSnapshotId=7578869; lastReplicationStartTimeInUsecs=1636345950391501; lastReplicationEndTimeInUsecs=1636346268736096; stats=}}
syncReplications        :
annotations             : {}
stats                   : @{hypervisor_avg_io_latency_usecs=-1; num_read_iops=-1; hypervisor_write_io_bandwidth_kBps=-1; timespan_usecs=-1; controller_num_read_iops=-1; read_io_ppm=-1; controller_num_iops=-1; total_read_io_time_usecs=-1;
                          controller_total_read_io_time_usecs=0; replication_transmitted_bandwidth_kBps=0; hypervisor_num_io=-1; controller_total_transformed_usage_bytes=-1; controller_num_write_io=-1; avg_read_io_latency_usecs=-1;
                          controller_total_io_time_usecs=0; controller_total_read_io_size_kbytes=0; controller_num_seq_io=-1; controller_read_io_ppm=-1; controller_total_io_size_kbytes=0; controller_num_io=0; hypervisor_avg_read_io_latency_usecs=-1;
                          num_write_iops=-1; controller_num_random_io=0; num_iops=-1; replication_received_bandwidth_kBps=0; hypervisor_num_read_io=-1; hypervisor_total_read_io_time_usecs=-1; controller_avg_io_latency_usecs=-1; num_io=-1;
                          controller_num_read_io=0; hypervisor_num_write_io=-1; controller_seq_io_ppm=-1; controller_read_io_bandwidth_kBps=-1; live_used_bytes=-1; controller_io_bandwidth_kBps=-1; hypervisor_timespan_usecs=-1;
                          hypervisor_num_write_iops=-1; replication_num_transmitted_bytes=0; total_read_io_size_kbytes=-1; hypervisor_total_io_size_kbytes=-1; avg_io_latency_usecs=-1; hypervisor_num_read_iops=-1; controller_write_io_bandwidth_kBps=-1;
                          controller_write_io_ppm=-1; hypervisor_avg_write_io_latency_usecs=-1; hypervisor_total_read_io_size_kbytes=-1; read_io_bandwidth_kBps=-1; hypervisor_num_iops=-1; hypervisor_io_bandwidth_kBps=-1; controller_num_write_iops=-1;
                          total_io_time_usecs=-1; snapshot_used_bytes=-1; controller_random_io_ppm=-1; controller_avg_read_io_size_kbytes=-1; total_transformed_usage_bytes=-1; avg_write_io_latency_usecs=-1; num_read_io=-1; write_io_bandwidth_kBps=-1;
                          hypervisor_read_io_bandwidth_kBps=-1; random_io_ppm=-1; total_untransformed_usage_bytes=-1; hypervisor_total_io_time_usecs=-1; num_random_io=-1; controller_avg_write_io_size_kbytes=-1; controller_avg_read_io_latency_usecs=-1;
                          num_write_io=-1; total_io_size_kbytes=-1; io_bandwidth_kBps=-1; replication_num_received_bytes=0; controller_timespan_usecs=0; num_seq_io=-1; seq_io_ppm=-1; write_io_ppm=-1; controller_avg_write_io_latency_usecs=-1}
usageStats              : @{lws_store_used_bytes=0; dr.exclusive_snapshot_usage_bytes=219134070784; hydration_space_bytes=-1}
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Retrieving PE Protection Domains."
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Get Protection Domain Schedule
##################################################################

Function REST-Get-Pe-ProtecionDomain-Schedules {
<#
.SYNOPSIS
Retrieves the schedules for a given protection domain. 

.DESCRIPTION
Pulls the schedule objects from the protection domain, in array format.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
PdName the name of the Protection Domain

.EXAMPLE
REST-Get-Pe-ProtecionDomain-Schedules `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PdName $pdname
'14-Nov-21 13:25:54' | INFO  | Getting Schedules of PD with name ''

suspended            : False
pdName               : xxxxx-NXC000-Gold_CCG
id                   : 0855b5d2-cd7d-40cf-9594-23865d91e403
type                 : HOURLY
values               :
everyNth             : 2
userStartTimeInUsecs : 16368143240
startTimesInUsecs    : {16368143000}
endTimeInUsecs       :
retentionPolicy      : @{localMaxSnapshots=24; remoteMaxSnapshots=; localRetentionPeriod=; remoteRetentionPeriod=; localRetentionType=; remoteRetentionType=}
appConsistent        : False
rollupScheduleUuid   :
isRollupSched        :

suspended            : False
pdName               : xxxxxxx-NXC000-Gold_CCG
id                   : 01cbd729-cb77-4868-b7cc-42501e1814d7
type                 : DAILY
values               :
everyNth             : 1
userStartTimeInUsecs : 16368143240
startTimesInUsecs    : {16368143000}
endTimeInUsecs       :
retentionPolicy      : @{localMaxSnapshots=35; remoteMaxSnapshots=; localRetentionPeriod=; remoteRetentionPeriod=; localRetentionType=; remoteRetentionType=}
appConsistent        : False
rollupScheduleUuid   :
isRollupSched        :

#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName
  )

  write-log -message "Getting Schedules of PD with name '$($PdName)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)/schedules"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}


##################################################################
# Pe Delete Protection Domain Schedule
##################################################################

Function REST-Delete-Pe-ProtecionDomain-Schedule {
<#
.SYNOPSIS
Deletes the schedule for a given protection domain based on schedule uuid

.DESCRIPTION
Deletes the schedule objects from the protection domain, in array format.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
PdName the name of the Protection Domain

.PARAMETER ScheduleUuid
ScheduleUuid uuid of the schedule use REST-Get-Pe-ProtecionDomain-Schedules to retrieve

.EXAMPLE
REST-Delete-Pe-ProtecionDomain-Schedule `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PdName $PdName `
  -ScheduleUuid 0855b5d2-cd7d-40cf-9594-23865d91e403
'14-Nov-21 13:33:04' | INFO  | Deleting Schedule '0855b5d2-cd7d-40cf-9594-23865d91e403' from Protection Domain with name 'RETSE124-NXC000-Gold_CCG'

value
-----
 True
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName,
    [parameter(mandatory)] [string] $ScheduleUuid
  )

  write-log -message "Deleting Schedule '$ScheduleUuid' from Protection Domain with name '$($PdName)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)/schedules/$ScheduleUuid"
    Method               = "DELETE"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Pe Add Protection Domain Schedule
##################################################################

Function REST-Add-Pe-ProtecionDomain-Schedule {
<#
.SYNOPSIS
Adds a schedule towards a given protection domain based

.DESCRIPTION
Creates a schedule Object Uuid.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
PdName the name of the Protection Domain

.PARAMETER Acg
Boolean, changes the snaps to Application Consistent snaps.

.PARAMETER IntervalType
HOURLY or DAILY Interval type of the backup schedule

.PARAMETER IntervalValue
Nr of Snaps per interval type. e.g. 5 per day, or 2 per hour. 

.PARAMETER LocalSnaps
Nr of snaps to keep locally

.PARAMETER RemoteSnaps
Nr of snaps to keep Remotely

.PARAMETER RemoteSiteName
Name of the remote site.

.EXAMPLE
REST-Add-Pe-ProtecionDomain-Schedule `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PdName $PdName `
  -Acg $Acg `
  -IntervalType $Schedule.IntervalType `
  -IntervalValue $Schedule.Interval `
  -LocalSnaps $Schedule.LocalCount `
  -RemoteSnaps $Schedule.RemoteCount `
  -RemoteSiteName "RS_$($TargetSitename)"
'14-Nov-21 13:48:16' | INFO  | Creating Schedule Interval Type 'HOURLY' inside Protection Domain with name 'RETSE124-NXC000-Gold_CCG'
'14-Nov-21 13:48:16' | INFO  | Replication will start at '11/15/2021 03:48:16'
'14-Nov-21 13:48:16' | INFO  | EPOCH '16369444960'

suspended            :
pdName               : RETSE124-NXC000-Gold_CCG
id                   : 206c3e91-ba9c-4da8-9191-3f24d7a4b1f0
type                 : HOURLY
values               : {32}
everyNth             : 2
userStartTimeInUsecs : 16369444960
startTimesInUsecs    :
endTimeInUsecs       :
retentionPolicy      : @{localMaxSnapshots=24; remoteMaxSnapshots=; localRetentionPeriod=; remoteRetentionPeriod=; localRetentionType=NUM_SNAPSHOTS; remoteRetentionType=}
appConsistent        : False
timezoneOffset       : 7200
rollupScheduleUuid   :
isRollupSched        : False
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $PdName,   
                           [bool]   $Acg = $false,
    [parameter(mandatory)] [string] $IntervalType,
    [parameter(mandatory)] [int]    $IntervalValue,
    [parameter(mandatory)] [int]    $LocalSnaps,
    [parameter(mandatory)] [int]    $RemoteSnaps,
    [parameter(mandatory)] [String] $RemoteSiteName
  )

  write-log -message "Creating Schedule Interval Type '$IntervalType' inside Protection Domain with name '$($PdName)'"
  
  $date = (get-date).addhours(14)
  $schedulestart = (Get-Date -Date $date -UFormat '%s').Replace((Get-Culture).NumberFormat.NumberDecimalSeparator,'') + "0"

  write-log -message "Replication will start at '$($date)'"
  write-log -message "EPOCH '$schedulestart'"

  if ($RemoteSnaps -gt 0 -and $RemoteSiteName -ne "RS_NONE"){
    $Remote = @{
      "$($RemoteSiteName)" = $RemoteSnaps
    }
  } else {
    $Remote = @{}
  }

  $PsHashPayload = @{
    pdName = $PdName
    type = $IntervalType
    values = $null
    everyNth = $IntervalValue
    userStartTimeInUsecs = $schedulestart
    startTimesInUsecs = $null
    timezoneOffset = 7200
    retentionPolicy = @{
      localMaxSnapshots = $LocalSnaps
      remoteMaxSnapshots = $Remote 
    }
    rollupScheduleUuid = $null 
    appConsistent = $Acg
  }

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdName)/schedules"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Create snapshot for protection domain
##################################################################

Function REST-Create-Pe-ProtecionDomain-SnapShot {
<#
.SYNOPSIS
Create a Snapshot towards a given protection domain

.DESCRIPTION
Calculates the time for the replication to start and creates a local and remote snapshot of the remote site is present in the PD.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PdName
PdName the name of the Protection Domain

.EXAMPLE
REST-Create-Pe-ProtecionDomain-SnapShot `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -PdObj $Pd
'14-Nov-21 14:52:00' | INFO  | Creating a PD Snapshot inside :'xxxx-NXC000-Gold_CCG'
'14-Nov-21 14:52:00' | INFO  | Replication will start at     : '11/14/2021 13:53:00'
'14-Nov-21 14:52:00' | INFO  | EPOCH                         : '16368979810'

scheduleId                : 7596243
scheduleStartTimeUsecs    : 1636897921042000
remoteSiteNames           : {RS_xxxxx-NXC000}
snapshotRetentionTimeSecs : 172800
appConsistent             : False
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $PdObj
  )

  write-log -message "Creating a PD Snapshot inside :'$($PdObj.name)'"
  
  $date = (get-date).addminutes(1).ToUniversalTime()
  $schedulestart = (Get-Date -Date $date -UFormat '%s').Replace((Get-Culture).NumberFormat.NumberDecimalSeparator,'') + "0"

  write-log -message "Replication will start at     : '$($date)'"
  write-log -message "EPOCH                         : '$schedulestart'"

  $RemoteSiteName = $PdObj.remoteSiteNames | select  -first 1
  
  $PsHashPayload = @{
    remoteSiteNames = @($RemoteSiteName)
    scheduleStartTimeUsecs = $schedulestart
    snapshotRetentionTimeSecs = 172800
    appConsistent = $false
  }


  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/protection_domains/$($PdObj.Name)/oob_schedules"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}


##################################################################
# Prx Create Remote Site
##################################################################

Function REST-Create-Prx-RemoteSite {
<#
.SYNOPSIS
Retrieves Detailed Remote Site Object for the PE Specified in the ProxyCluster Uuid

.DESCRIPTION
V1 API action. 

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
Cluster Uuid the uuid of the cluster to proxy towards

.PARAMETER RemoteSiteName
RemoteSiteName Name of the Protection Domain being deleted.

.PARAMETER TargetIp 
TargetIp Target IP for the remote site

.PARAMETER TargetPort
Target port for the remote site connection

.PARAMETER CompressionEnabled
Boolean Enables / Disables compression on the Remote Site Link


.EXAMPLE
REST-Create-Prx-RemoteSite `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -ClusterUuid $ReplicationTarget.metadata.uuid `
  -RemoteSiteName "BPAutonomics" `
  -TargetIp 1.1.1.1
'14-Nov-21 15:05:35' | INFO  | Creating Remote Site : 'BPAutonomics' through PC Proxy, Cluster target '0005aa62-797b-1f9a-6c01-48df37c63270'

name                                 : BPAutonomics
uuid                                 : 0005d0a0-76ec-e236-163b-48df37e13b30
remoteIpPorts                        : @{1.1.1.1=2020}
remoteIpAddressPorts                 : @{1.1.1.1=2020}
cloudType                            :
proxyEnabled                         : False
compressionEnabled                   : True
sshEnabled                           : False
vstoreNameMap                        :
maxBps                               :
clusterArch                          : X86_64
markedForRemoval                     : False
clusterId                            : 1601954216012757808
clusterIncarnationId                 : 1636762492133942
replicationLinks                     : {}
capabilities                         : {BACKUP, METRO_AVAILABILITY, SUPPORT_DEDUPED_EXTENTS, SUPPORT_KVM}
status                               : relationship established
latencyInUsecs                       : 196
remoteVStoreInfo                     : @{SelfServiceContainer=; NutanixManagementShare=}
metroReady                           : True
bandwidthPolicy                      :
bandwidthPolicyEnabled               : False
networkMapping                       :
clusterExternalDataServicesIPAddress : 1.1.1.1
clusterExternalDataServicesAddress   : @{ipv4=1.1.1.1}
remoteDrExternalSubnet               :
remoteDrExternalSubnetAddress        :
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid,
    [parameter(mandatory)] [string] $RemoteSiteName,
    [parameter(mandatory)] [string] $TargetIp,
                           [int]    $TargetPort = 2020,
                           [Bool]   $CompressionEnabled = $true,
                           [Bool]   $SshEnabled = $false,
                           [Bool]   $ProxyEnabled = $false 

  )

  write-log -message "Creating Remote Site : '$($RemoteSiteName)' through PC Proxy, Cluster target '$($ClusterUUID)'"

  $PsHashPayload = @{
    name = $RemoteSiteName
    vstoreNameMap = @{}
    remoteIpPorts = @{
      "$TargetIp" = $TargetPort
    }
    maxBps = $null 
    proxyEnabled = $ProxyEnabled
    bandwidthPolicy = $null
    compressionEnabled = $CompressionEnabled
    sshEnabled = $SshEnabled
    capabilities = @("BACKUP")
    networkMapping = @{
      uuid = $null 
      l2NetworkMappings = @()
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/PrismGateway/services/rest/v1/remote_sites?proxyClusterUuid=$($ClusterUuid)"
    Method               = "POST"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Px Health Check Specs
##################################################################

Function REST-Get-Px-Ncc-HealthCheck-Specs {
<#
.SYNOPSIS
Pulls the health check specs from the Prism Central or Element API

.DESCRIPTION
At the time of writing this returns 723 different health checks. 

.PARAMETER PxClusterIp
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-Ncc-HealthCheck-Specs `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead

id                          : 0005ba33-a0b7-8458-0548-48df37c60a60::130080
policyUuid                  :
name                        : Datastore Remount Success
description                 : Remounted datastore.
title                       : Remounted Datastore
applicableForMultiCluster   : False
applicableForSingleCluster  : True
enabled                     : True
autoResolve                 : not_supported
isUserDefined               : False
checkType                   : event_driven
affectedEntityTypes         : {container}
categoryTypes               : {SystemIndicator, Storage}
subCategoryTypes            : {Data Protection-Protection Domain}
scope                       : kCluster
parameters                  :
kbList                      : {}
causes                      : {Datastore has been remounted}
resolutions                 : {As the datastore has been mounted successfully rescan the datastore in vCenter in order to complete the changes necessary to support the enhanced planned failover functionality}
modifiedTimeStampInUsecs    : 1629845610239275
modifiedByUsername          : Nutanix
alertTypeId                 : A130080
isGlobalConfig              : False
message                     : Remounted Datastore '{datastore_name}' as metro availability is being enabled.
severityThresholdInfos      : {@{severity=kCritical; enabled=}, @{severity=kWarning; enabled=}, @{severity=kInfo; enabled=True}}
alertConfigurableParameters : {}
exceptionCount              : 0
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  # Silent Module
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/health_checks"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Px Health Check Last Run
##################################################################

Function REST-Get-Px-Ncc-HealthCheck-LastRun {
<#
.SYNOPSIS
Pulls the health check specs from the Prism Central or Element API

.DESCRIPTION
At the time of writing this returns 723 different health checks. 

.PARAMETER PxClusterIp
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-Ncc-HealthCheck-LastRun `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead

entityType        healthSummary                                         detailedCheckSummary
----------        -------------                                         --------------------
HOST              @{Critical=0; Warning=0; Error=0; Good=3; Unknown=0}  @{15021=; 15023=; 6511=; 15022=; 111079=; 21021=; 1066=; 1064=; 111080=; 111087=; 111088=; 15028=; 1110…
DISK              @{Critical=0; Warning=0; Error=0; Good=12; Unknown=0} @{1005=; 6515=; 6514=; 1009=}
VM                @{Critical=0; Warning=1; Error=0; Good=32; Unknown=0} @{3060=; 110268=; 2001=; 3020=; 3041=; 110217=; 3040=; 3061=}
REMOTE_SITE       @{Critical=0; Warning=0; Error=0; Good=2; Unknown=0}  @{110002=; 110014=; 110001=; 130018=; 130063=}
PROTECTION_DOMAIN @{Critical=0; Warning=1; Error=0; Good=0; Unknown=0}  @{130088=; 110204=; 130044=; 110266=; 110200=; 110222=; 110244=; 130046=; 110265=; 110254=; 110243=; 11…
STORAGE_POOL      @{Critical=0; Warning=0; Error=0; Good=1; Unknown=0}  @{1016=; 101047=}
CONTAINER         @{Critical=0; Warning=0; Error=0; Good=3; Unknown=0}  @{1028=; 1017=; 1026=; 110210=}
CLUSTER           @{Critical=0; Warning=0; Error=0; Good=1; Unknown=0}  @{21023=; 111078=; 110022=; 106047=; 110265=; 160087=; 160088=; 160089=; 160090=; 160091=; 21020=; 1110…
VOLUME_GROUP      @{Critical=0; Warning=0; Error=0; Good=1; Unknown=0}  @{101056=}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  # Silent Module
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/ncc/run_summary?detailedSummary=true"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Disable Px Health Check Last Run
##################################################################

Function REST-Disable-Px-Ncc-HealthCheck {
<#
.SYNOPSIS
Disables a health check, Use HealthCheck-Spec as input

.DESCRIPTION
At the time of writing this returns 723 different health checks. 

.PARAMETER PxClusterIp
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Check
Check use REST-Get-Px-Ncc-HealthCheck-Specs to filter the check you wish to disable.

.EXAMPLE
REST-Disable-Px-Ncc-HealthCheck `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -Check $check
'14-Nov-21 16:07:39' | INFO  | Disabling Check : '0005ba33-a0b7-8458-0548-48df37c60a60::110268'

id                          : 0005ba33-a0b7-8458-0548-48df37c60a60::110268
policyUuid                  :
name                        : Protected VM CBR Incapable
description                 : Some of the protected VMs are not capable of backup and recovery.
title                       : Protected VM is not capable of backup and recovery.
applicableForMultiCluster   : False
applicableForSingleCluster  : True
enabled                     : False
autoResolve                 : enabled
isUserDefined               : False
checkType                   : scheduled
scheduleIntervalInSecs      : 86400
affectedEntityTypes         : {vm}
categoryTypes               : {SystemIndicator, DR}
subCategoryTypes            : {Data Protection-Protection Domain}
scope                       : kNode
parameters                  :
kbList                      : {http://portal.nutanix.com/kb/7635}
causes                      : {Not all protected VMs have a valid configuration for backup and recovery}
resolutions                 : {Review and update the VM configuration. If the configuration of the VM cannot be changed then unprotect the VMs.}
modifiedTimeStampInUsecs    : 1636902459998000
modifiedByUsername          : svc_build
alertTypeId                 : A110268
isGlobalConfig              : False
message                     : Protected VM {vm_name} is not capable of backup and recovery. Reason: {cbr_incapable_reason}
severityThresholdInfos      : {@{severity=kCritical; enabled=}, @{severity=kWarning; enabled=True}, @{severity=kInfo; enabled=}}
alertConfigurableParameters : {}
exceptionCount              : 0
alertConfigExceptionGroups  : {}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [object] $Check
  )

  $Check.enabled = "false"
  write-log -message "Disabling Check : '$($Check.id)'"
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/health_checks"
    Method               = "PUT"
    Body                 = $Check
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}


##################################################################
# Get Proxy Whitelist
##################################################################

Function REST-Get-Px-Proxy-WhiteList {
<#
.SYNOPSIS
Pulls the current proxy whitelist from Prism Element or Central

.DESCRIPTION
Self Explanatory

.PARAMETER PxClusterIp
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-Proxy-WhiteList `
  -PxClusterIP $PxClusterIp `
  -AuthHeader $BasicHead
'14-Nov-21 20:22:41' | INFO  | Pulling Proxy Whitelist.

whitelist
---------
{} 
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Pulling Proxy Whitelist."
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/http_proxies/whitelist"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Set Proxy Whitelist
##################################################################

Function REST-Set-Px-Proxy-WhiteList {
<#
.SYNOPSIS
Pulls the current proxy whitelist from Prism Element or Central

.DESCRIPTION
Self Explanatory

.PARAMETER PxClusterIp
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-Proxy-WhiteList `
  -PxClusterIP $PxClusterIp `
  -AuthHeader $BasicHead
'14-Nov-21 20:22:41' | INFO  | Pulling Proxy Whitelist.

whitelist
---------
{} 
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
                          [Array]   $DomainWildArr,
                          [Array]   $NameArr,
                          [Array]   $IPArr
  )
  write-log -message "Configuring Proxy Whitelist."

  [array]$WhitelistArray = $null

  foreach ($item in $DomainWildArr){
    $WhiteListEntry = @{
      target = $item
      targetType = "DOMAIN_NAME_SUFFIX"
    }
  }

  foreach ($item in $NameArr){
    $WhiteListEntry = @{
      target = $item
      targetType = "HOST_NAME"
    }
    $WhitelistArray += $WhiteListEntry
  }

  foreach ($item in $IPArr){
    $WhiteListEntry = @{
      target = $Item
      targetType = "IPV4_ADDRESS"
    }
    $WhitelistArray += $WhiteListEntry
  } 

  $WhiteList = @{
    whitelist = $WhitelistArray
  }
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/http_proxies/whitelist"
    Method               = "PUT"
    Body                 = $WhiteList
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Set Proxy Config
##################################################################

Function REST-Set-Px-Proxy-Config {
<#
.SYNOPSIS
Sets the current proxy whitelist from Prism Element or Central

.DESCRIPTION
Self Explanatory

.PARAMETER PxClusterIp
PxClusterIp is the name or IP for the Prism Element or Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE

#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ProxyName,
    [parameter(mandatory)] [string] $ProxyIP,
    [parameter(mandatory)] [string] $ProxyPort
  )

  $PsHashPayload = @{
    name = $ProxyName
    address = $ProxyIP
    port = $ProxyPort
    username = $null 
    password = $null 
    proxyTypes = @(
      "http"
      "https"
    )
  }

  write-log -message "Setting Proxy Config."
  
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/http_proxies/whitelist"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Pc User Groups
##################################################################

Function REST-Get-Pc-UserGroup {
<#
.SYNOPSIS
Pulls the user groups from Prism Central, these are AD groups that have Prism Object identifiers.

.DESCRIPTION
Returns a V3 result object. Uses Pagination functions.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pc-UserGroup `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead
'14-Nov-21 20:56:14' | INFO  | Building UserGroup Query JSON
'14-Nov-21 20:56:14' | INFO  | Converting Object
'14-Nov-21 20:56:14' | INFO  | Post Body is 'System.String'
'14-Nov-21 20:56:14' | INFO  | We found '11' items.

Name                           Value
----                           -----
entities                       {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=}…}
api_version                    3.1
metadata                       {length, total_matches, kind, offset}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Building UserGroup Query JSON"

  $PsHashPayload = @{
    kind = "user_group"
    offset = 0
    length = 50
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/user_groups/list"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Pc User Groups
##################################################################

Function REST-Get-Pc-Users {
<#
.SYNOPSIS
Pulls the user objects from Prism Central, these are AD users that have Prism Object identifiers.

.DESCRIPTION
Returns a V3 result object. Uses Pagination functions.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pc-Users `
  -PcClusterIp $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead
'14-Nov-21 21:00:40' | INFO  | Building User Query JSON
'14-Nov-21 21:00:40' | INFO  | Converting Object
'14-Nov-21 21:00:41' | INFO  | Post Body is 'System.String'
'14-Nov-21 21:00:41' | INFO  | We found '11' items.

Name                           Value
----                           -----
entities                       {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=}…}
api_version                    3.1
metadata                       {length, total_matches, kind, offset}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Building User Query JSON"

  $PsHashPayload = @{
    kind = "user"
    offset = 0
    length = 50
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/users/list"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Update Pe Dataservices IP
##################################################################

Function REST-Update-PE-DataServices-IP {
<#
.SYNOPSIS
Updates the cluster object with the data services IP.

.DESCRIPTION
Does a patch on the cluster object, changing only the value specified, API V1 Based

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ClusterUuid
ClusterUuid uuid of the cluster to pull detailed info from.

.PARAMETER DataIp
Data services IP

.EXAMPLE
REST-Update-PE-DataServices-IP `
  -PeClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -ClusterUuid $ClusterDetail.uuid `
  -DataIp $Mainvars.cluster.DataServicesIp
'14-Nov-21 21:08:20' | INFO  | Inserting '10.230.38.103' IP into Cluster '0005d0a0-76ec-e236-163b-48df37e13b30' object.

value
-----
 True

#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ClusterUuid,
    [parameter(mandatory)] [string] $DataIp
  )

  write-log -message "Inserting '$DataIp' IP into Cluster '$($ClusterUuid)' object."

  $PsHashPayload = @{
    clusterUuid = $ClusterUuid
    genericDTO = @{
      clusterExternalDataServicesIPAddress = $DataIp
    }
    operation = "EDIT"
  }

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/cluster"
    Method               = "PATCH"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Update Prism SMTP alert config
##################################################################

Function REST-Set-Px-SMTP-AlertConfig {
<#
.SYNOPSIS
Updates SMTP alert settings in Prism Element or Central

.DESCRIPTION
Sets the SMTP Config for Prism Alerts. Both Prism Element and Prism Central are supported.

.PARAMETER PxClusterIP
PxClusterIP is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER SmtpReceiver
SmtpReceiver Recipient of the SMTP messages

.PARAMETER SmtpSender
SmtpSender Sender of the SMTP messages

.PARAMETER SmtpPort
SmtpPort port for the SMTP Server

.PARAMETER SmtpServer
SmtpServer host that handles the SMTP messages.

.PARAMETER SmptUser
SmptUser set value to "none" in case auth is not needed.

.PARAMETER SmtpPass
SmtpPass set value to "none" in case auth is not needed.

.PARAMETER Security   
Security NONE STARTTLS SSL

.EXAMPLE
REST-Set-Px-SMTP-AlertConfig `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -SmtpReceiver $MainVars.Recipients.AlertReceiverEmail `
  -SmtpSender $senderemail `
  -SmptUser $Username `
  -SmtpPass $Password `
  -SmtpPort $MainVars.Recipients.SmtpPort `
  -SmtpServer $MainVars.Recipients.SmtpServer `
  -Security $MainVars.Recipients.SmtpSecurity
'14-Nov-21 21:38:37' | INFO  | Configuring SMTP Alert Settings

enable                    : False
enableEmailDigest         : True
enableDefaultNutanixEmail : True
defaultNutanixEmail       : nos-alerts@nutanix.com
emailContactList          : {xxxx.com}
smtpServer                : @{address=smtp-gw.xxxx; serverAddress=; port=25; username=; password=; secureMode=NONE; fromEmailAddress=xxxx.com;
                            emailStatus=}
tunnelDetails             : @{httpProxy=; serviceCenter=; connectionStatus=; transportStatus=}
emailConfigRules          :
emailTemplate             : @{subjectPrefix=; bodySuffix=}
skipEmptyAlertEmailDigest : True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $SmtpReceiver,
    [parameter(mandatory)] [string] $SmtpSender,
    [parameter(mandatory)] [string] $SmtpPort = 25,
    [parameter(mandatory)] [string] $SmtpServer,
    [parameter(mandatory)] [string] $SmptUser,
    [parameter(mandatory)] [string] $SmtpPass,
    [parameter(mandatory)] [string] $Security
  )

  write-log -message "Configuring SMTP Alert Settings"

  $PsHashPayload = @{
    emailContactList = @($SMTPReceiver)
    enable = $False
    enableDefaultNutanixEmail = $true
    skipEmptyAlertEmailDigest = $true
    defaultNutanixEmail = "nos-alerts@nutanix.com"
    smtpserver = @{
      address = $SmtpServer
      port = $SmtpPort
      username = $SmptUser
      password = $SmtpPass
      secureMode  = $Security
      fromEmailAddress = $SmtpSender
      emailStatus = @{
        status = "UNKNOWN"
        message = $null
      }
    }
    tunnelDetails = @{
      httpProxy = $null
      serviceCenter = $null
      connectionStatus = @{
        lastCheckedTimeStampUsecs = 0
        status = "UNKNOWN"
        message = $null
      }
      transportStatus = @{
        status = "UNKNOWN"
        message = $null
      }
    }
    emailConfigRules = $null
    emailTemplate = @{
      subjectPrefix = $null 
      bodySuffix = $null
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/alerts/configuration"
    Method               = "PUT"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Update Prism SMTP alert config
##################################################################

Function REST-Set-Px-SMTP-Config {
<#
.SYNOPSIS
Updates SMTP settings in Prism Element or Central

.DESCRIPTION
Compatible with both Element and Central

.PARAMETER PxClusterIP
PxClusterIP is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER SmtpReceiver
SmtpReceiver Recipient of the SMTP messages

.PARAMETER SmtpSender
SmtpSender Sender of the SMTP messages

.PARAMETER SmtpPort
SmtpPort port for the SMTP Server

.PARAMETER SmtpServer
SmtpServer host that handles the SMTP messages.

.PARAMETER SmptUser
SmptUser set value to "none" in case auth is not needed.

.PARAMETER SmtpPass
SmtpPass set value to "none" in case auth is not needed.

.PARAMETER Security   
Security NONE STARTTLS SSL

.EXAMPLE
REST-Set-Px-SMTP-Config `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -SmtpReceiver $MainVars.Recipients.AlertReceiverEmail `
  -SmtpSender $SenderEmail `
  -SmptUser $Username `
  -SmtpPass $Password `
  -SmtpPort $MainVars.Recipients.SmtpPort `
  -SmtpServer $MainVars.Recipients.SmtpServer `
  -Security $MainVars.Recipients.SmtpSecurity
'15-Nov-21 12:44:55' | INFO  | Configuring SMTP Settings

address          : smtp-gw.xxxx.com
serverAddress    : @{hostname=smtp-gw.xxx.com}
port             : 25
username         :
password         :
secureMode       : NONE
fromEmailAddress : xxx-xx@xxxx.xxx.com
emailStatus      : @{status=UNKNOWN; message=}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $SmtpReceiver,
    [parameter(mandatory)] [string] $SmtpSender,
                           [string] $SmtpPort = 25,
    [parameter(mandatory)] [string] $SmtpServer,
    [parameter(mandatory)] [string] $SmptUser,
    [parameter(mandatory)] [string] $SmtpPass,
    [parameter(mandatory)] [string] $Security
  )

  write-log -message "Configuring SMTP Settings"

  $PsHashPayload = @{
    address = $SmtpServer
    port = $SmtpPort
    username = $SmptUser
    password = $SmtpPass
    secureMode  = $Security
    fromEmailAddress = $SmtpSender
    emailStatus = @{
      status = "UNKNOWN"
      message = $null
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/cluster/smtp"
    Method               = "PUT"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Create PE Network
##################################################################

Function REST-Create-Pe-Network {
<#
.SYNOPSIS
Creates a Prism Element Network

.DESCRIPTION
Compatible with both Element and Central

.PARAMETER PxClusterIP
PxClusterIP is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Create-Pe-Network `
  -PeClusterIP $MainVars.Cluster.PeClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -Ipam $false `
  -Name "TestBPAutonomics" `
  -VLanId 109
'30-Dec-21 21:39:17' | INFO  | Nutanix IPAM Disabled!
'30-Dec-21 21:39:17' | INFO  | Creating a Nutanix Network on vlan '109'

networkUuid
-----------
dc152035-c409-47cc-a423-e57c28484385
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
                           [bool]   $Ipam,
                           [string] $SubnetMask,
                           [string] $GateWay,
                           [string] $DhcpStart,
                           [string] $DhcpEnd,
    [parameter(mandatory)] [string] $Name,
    [parameter(mandatory)] [string] $VLanId,
                           [string] $Address,
                           [String] $DnsServers,
                           [string] $Domain,
                           [string] $Prefix
  )

  if ($IPAM -eq $true){

    write-log -message "VLAN: '$($VLanId)' Prefix: '$Prefix'"
    write-log -message "Gateway: '$($GateWay)' Address: '$Address'"
    write-log -message "DHCPStart: '$($DhcpStart)' DHCPEnd: '$DhcpEnd'"
    write-log -message "Domain: '$($Domain)' DNS: '$DnsServers'"
    write-log -message "Nutanix IPAM Enabled!"

    $PsHashPayload = @{
      name = $Name
      vlanId = $VLanId
      ipConfig = @{
        dhcpOptions = @{
          domainNameServers = $DnsServers
          domainname = $Domain
        }
        networkAddress = $Address
        prefixLength = $Prefix
        defaultGateway = $GateWay
        pool = @(@{
          range = "$($DHCPStart) $($DHCPEnd)"
        })
      }
    }

  } else {

    write-log -message "Nutanix IPAM Disabled!"
    write-log -message "Creating a Nutanix Network on vlan '$VLanId'"

    $PsHashPayload = @{
      name = $Name
      vlanId = $VLanId
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/api/nutanix/v0.8/networks"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Run NCC All Checks
##################################################################

Function REST-Run-Pe-Ncc-HealthChecks {
<#
.SYNOPSIS
Executes NCC Checks on a Prism Element or Central Instance

.DESCRIPTION
Runs Async, results needs to be retrieved with REST-Get-Px-Ncc-HealthCheck-LastRun

.PARAMETER PxClusterIP
PxClusterIP is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Run-Pe-Ncc-HealthChecks `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'15-Nov-21 15:34:15' | INFO  | Executing NCC on '10.230.38.71'

taskUuid
--------
9eb231f9-d2df-4926-951b-ae3eef5b327b

#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Executing NCC on '$PxClusterIP'"

  $PsHashPayload = @{
    sendEmail = $false
  }
  

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/ncc/checks"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Px Alerts API V3 Group Call
##################################################################

Function REST-Get-Px-AlertsGroup {
<#
.SYNOPSIS
Pulls all Prism Alerts using a group call. 

.DESCRIPTION
API V1 group call to pull alerts that are not resolved.

.PARAMETER PxClusterIP
PxClusterIP is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Px-AlertsGroup `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'15-Nov-21 20:18:35' | INFO  | Executing Alert Query using Group Call

total_entity_count    : 18
filtered_entity_count : 9
total_group_count     : 1
entity_type           : alert
group_results         : {@{total_entity_count=9; group_by_column_value=; group_summaries=; entity_results=System.Object[]}}
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Executing Alert Query using Group Call"

  $PsHashPayload = @{
    entity_type = "alert"
    query_name = (new-guid).guid
    grouping_attribute = ""
    group_count = 3
    group_offset = 0
    group_attributes = @()
    group_member_count = 50
    group_member_offset = 0
    group_member_attributes = @(@{
      attribute = "alert_title"
    }
    @{
      attribute = "affected_entities"
    }
    @{
      attribute = "impact_type"
    }
    @{      
      attribute = "severity"
    }
    @{
      attribute = "resolved"
    }
    @{
      attribute = "acknowledged"
    }
    @{
      attribute = "created_time_stamp"
    }
    @{
      attribute = "clusterName"
    }
    @{
      attribute = "auto_resolved"
    })
    filter_criteria = "resolved==false"
  }
 
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/groups"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Resolve Px Alerts API V1 Group Call
##################################################################

Function REST-Resolve-Px-Alerts {
<#
.SYNOPSIS
Resolves the Alerts in the UUids Array

.DESCRIPTION
API V1 group call to resolve alerts

.PARAMETER PxClusterIP
PxClusterIP is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER Uuids 
Array of alert uuids.

.EXAMPLE
REST-Resolve-Px-Alerts `
  -PxClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -Uuids $Uuids
'15-Nov-21 20:28:32' | INFO  | Executing Alert Resolution on '9' Alerts

id                                   successful message
--                                   ---------- -------
6345dce9-7cfe-4e1b-bafc-2c4111ffb7ca       True
e57215c7-27c0-425c-9567-c9b6d81c5489       True
4aafd1f1-2260-40ba-ab40-d1fd6322af82       True
6dc5a2c1-eeff-4d03-8c25-5b48fc4725bc       True
07074a73-e5a5-41e6-85ec-78c3e9cf86a5       True
04d58090-1925-43c6-9dc5-c29329c63894       True
a2d1c00c-3605-4326-9796-2af0a0683829       True
1b197273-c4cb-4a99-93a6-be02e0eaba26       True
7cb84112-e2a6-469b-9b47-d360163f96f6       True
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Array]  $Uuids
  )

  write-log -message "Executing Alert Resolution on '$($uuids.count)' Alerts"
 
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/PrismGateway/services/rest/v1/alerts/resolve_list"
    Method               = "POST"
    Body                 = $($Uuids) | convertto-json -asarray
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Px Image Detail API V3
##################################################################

Function REST-Get-Px-Image-Detail {
<#
.SYNOPSIS
Resolves the Alerts in the UUids Array

.DESCRIPTION
API V1 group call to resolve alerts

.PARAMETER PxClusterIP
PxClusterIP is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ImageUuid
ImageUuid UUid of the image

.EXAMPLE
REST-Get-Px-Image-Detail `
  -PxClusterIP $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -ImageUuid 2b61689c-5b96-4577-8129-72ae2088de5d
'15-Nov-21 20:45:09' | INFO  | Pulling image detail using: '2b61689c-5b96-4577-8129-72ae2088de5d'

status                                                                                                             spec
------                                                                                                             ----
@{state=COMPLETE; name=ICC_2k16_v0015_DT-sadsad-NXC000; resources=; description=ICC_2k16_v0015_DT-dssad-NXC000} @{n…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [String] $ImageUuid
  )

  write-log -message "Pulling image detail using: '$ImageUuid'" 
 
  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/api/nutanix/v3/images/$($imageUUID)"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Mount Pe CdRom image
##################################################################

Function REST-Mount-Pe-CdRom-Image {
<#
.SYNOPSIS
Resolves the Alerts in the UUids Array

.DESCRIPTION
API V1 group call to resolve alerts

.PARAMETER PxClusterIP
PxClusterIP is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER ImageUuid
ImageUuid UUid of the image

.PARAMETER CdRomObj
A part of the VM Diskobject, that holds the CDROM. $CdRomObj.disk_address.vmdisk_uuid

.PARAMETER VmUuid
VmUuid to build 

.EXAMPLE
REST-Get-Px-Image-Detail `
  -PxClusterIP $MainVars.AutoDC.PcClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead `
  -ImageUuid 2b61689c-5b96-4577-8129-72ae2088de5d
'15-Nov-21 20:45:09' | INFO  | Pulling image detail using: '2b61689c-5b96-4577-8129-72ae2088de5d'

status                                                                                                             spec
------                                                                                                             ----
@{state=COMPLETE; name=dsaasdsa-sadsad-asdasd; resources=; description=asdasdsda-dssad-adasd} @{n…
#>
  Param (
    [parameter(mandatory)] [string] $PxClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [String] $VmUuid,
    [parameter(mandatory)] [object] $CdRomObj,
    [parameter(mandatory)] [object] $ImageObj
  )

  write-log -message "Mounting CD inside VM with ID $VmUuid"
  write-log -message "Using ISO $($ImageObj.Name)"

  $PsHashPayload = @{
    vm_disks = @(@{
      disk_address = @{
        vmdisk_uuid = $CdRomObj.disk_address.vmdisk_uuid
        device_index = $CdRomObj.disk_address.device_index
        device_bus = $CdRomObj.disk_address.device_bus
      }
      flash_mode_enabled = $false
      is_cdrom = $True 
      is_empty = $false
      vm_disk_clone = @{
        disk_address = @{
          vmdisk_uuid = $ImageObj.vmDiskId
        }
        minimum_size = $ImageObj.vmDiskSize
      }
    })
  }

  $RequestPayload = @{
    Uri                  = "https://$($PxClusterIP):9440/api/nutanix/v3/images/$($imageUUID)"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Px Image Detail API V3
##################################################################

Function REST-Get-Pe-Alert-Detail {
<#
.SYNOPSIS
Pulls the details of an alert. 

.DESCRIPTION
API V1 group call to resolve alerts

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER AlertUuid
AlertUuid UUid of the Alert, use REST-Get-Px-AlertsGroup to pull active alerts

.EXAMPLE
REST-Get-Pe-Alert-Detail `
  -PeClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -AlertUuid 6345dce9-7cfe-4e1b-bafc-2c4111ffb7ca
'15-Nov-21 21:10:31' | INFO  | Pulling alert detail using: '6345dce9-7cfe-4e1b-bafc-2c4111ffb7ca'

metadata                                                                                    entities
--------                                                                                    --------
@{grand_total_entities=1; total_entities=1; page=1; count=1000; start_index=1; end_index=1} {@{id=6345dce9-7cfe-4e1b-bafc-2c4111ffb7ca; alert_type_uuid=A111061; check_id=0005d…

#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [String] $AlertUuid
  )
  write-log -message "Pulling alert detail using: '$AlertUuid'" 
 
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIP):9440/PrismGateway/services/rest/v2.0/alerts?alert_ids=$($AlertUuid)&detailed_info=true"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Px Image Detail API V3
##################################################################

Function REST-Get-Pe-FaultTolerance-Status {
<#
.SYNOPSIS
Pulls the Fault Tolerance status of a prism element cluster. 

.DESCRIPTION
API V1 call, look for numberOfFailuresTolerable based on the object returned to see if cluster can tolorate Failures.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pe-FaultTolerance-Status `
  -PEClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'15-Nov-21 21:14:28' | INFO  | Pulling Fault Tolerance Status for Pe: 'x.x.x.x

domainType    componentFaultToleranceStatus                                                                                                    clusterUnderReplicatedDataBytes c
                                                                                                                                                                                                                                                                                                                                                       s
----------    -----------------------------                                                                                                    ------------------------------- -
NODE          @{STATIC_CONFIGURATION=; STARGATE_HEALTH=; OPLOG=; EXTENT_GROUPS=; ERASURE_CODE_STRIP_SIZE=; METADATA=; ZOOKEEPER=; FREE_SPACE=}                               0 0
RACKABLE_UNIT @{STATIC_CONFIGURATION=; STARGATE_HEALTH=; OPLOG=; EXTENT_GROUPS=; ERASURE_CODE_STRIP_SIZE=; METADATA=; ZOOKEEPER=; FREE_SPACE=}                               0 0
RACK          @{STATIC_CONFIGURATION=}                                                                                                                                       0 0
DISK          @{OPLOG=; EXTENT_GROUPS=; ERASURE_CODE_STRIP_SIZE=; METADATA=; FREE_SPACE=}                                                                                    0 0
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Pulling Fault Tolerance Status Pe: '$PeClusterIP'" 
 
  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/cluster/domain_fault_tolerance_status"
    Method               = "GET"
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Px Image Detail API V3
##################################################################

Function REST-Get-Pe-CVM-Ram {
<#
.SYNOPSIS
Pulls the CVM Ram Config of a prism element cluster. 

.DESCRIPTION
API V1 Genesis Call

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pe-CVM-Ram `
  -PeClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead
'15-Nov-21 21:23:19' | INFO  | Pulling Genesis Details CVM Ram Config.

value
-----
{".return": {"1.1.1.1": {"node_model": "HPE DX360-8 G10", "memory": 32, "is_node_light_compute": false, "name": "ntnx-cz20460b4v-a-cvm"}, "1.1.1.1": {"node_model": …
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Pulling Genesis Details CVM Ram Config."
 
  $PsHashPayload1 = @{
    ".oid" = "ClusterManager"
    ".method" = "get_cluster_cvm_params_map"
    ".kwargs" = @{
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Set Pe CVM Ram Config
##################################################################

Function REST-Set-Pe-CVM-Ram {
<#
.SYNOPSIS
Changes the CVM Ram Config of a prism element cluster. 

.DESCRIPTION
API V1 Genesis Call.
Do not use 64GB, or test it first. Nodes move to 63 GB if you do this.
You need to manually fix the values using VirtIO.

.PARAMETER PeClusterIp
PeClusterIp is the name or IP for the Prism Element Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER GbRam
GbRam Ram value in GB 32,36,40,48,64

.EXAMPLE
REST-Set-Pe-CVM-Ram `
  -PeClusterIp $MainVars.Cluster.PeClusterIp `
  -AuthHeader $MainVars.Creds.Password_Vault.Site_Pe_Svc.BasicHead `
  -GbRam 36
'15-Nov-21 21:58:57' | INFO  | Changing RAM using Genesis CVM Ram Config, new value: '36'
'15-Nov-21 21:58:57' | INFO  | CVMs will reboot, this is best done inside a maintenance window

value
-----
{".return": [true, null]}
#>
  Param (
    [parameter(mandatory)] [string] $PeClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $GbRam
  )

  write-log -message "Changing RAM using Genesis CVM Ram Config, new value: '$GbRam'"
  write-log -message "CVMs will reboot, this is best done inside a maintenance window"
 
  $PsHashPayload1 = @{
    ".oid" = "ClusterManager"
    ".method" = "reconfig_cvm"
    ".kwargs" = @{
      cvm_reconfig_json = @{
        target_memory_in_gb = $GbRam
      }
    }
  }
  $DoubleJson = $PsHashPayload1 | convertto-json -depth 10 -compress
  $PsHashPayload2 = @{
    value = $DoubleJson
  } 

  $RequestPayload = @{
    Uri                  = "https://$($PeClusterIp):9440/PrismGateway/services/rest/v1/genesis"
    Method               = "Post"
    Headers              = $AuthHeader
    Body                 = $PsHashPayload2
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Get Pc Permissions 
##################################################################

Function REST-Get-Pc-Permissions {
<#
.SYNOPSIS
Pulls all the permission objects from the PC API. This includes the uuids for creating a role.

.DESCRIPTION
This is the permissions api, undocumented and likely to change in the near future.

.PARAMETER PcClusterIp
PeClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pc-Permissions `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead
'18-Dec-21 16:12:24' | INFO  | Pulling all permission objects
'18-Dec-21 16:12:24' | INFO  | Converting Object
'18-Dec-21 16:12:26' | INFO  | We found '500' items.
'18-Dec-21 16:12:26' | INFO  | Api Pagination Required: '527' Vms Detected.
'18-Dec-21 16:12:26' | INFO  | We have collected '500' items.
'18-Dec-21 16:12:26' | INFO  | Loading another page.
'18-Dec-21 16:12:26' | INFO  | Converting Object
'18-Dec-21 16:12:26' | INFO  | We found '27' items.

Name                           Value
----                           -----
api_version                    3.1
entities                       {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata…
metadata                       {total_matches, kind, offset, length}
#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Pulling all permission objects"

  $PsHashPayload = @{
    kind = "permission" 
    length = 500
    offset = 0
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/permissions/list"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName) `
    -Count 500
}

##################################################################
# Get Pc Access Control Policies 
##################################################################

Function REST-Get-Pc-ACPs {
<#
.SYNOPSIS
Retrieves the list of access control policies in Prism Central

.DESCRIPTION
V3 based API with pagination. ACPs are not visible in the UI.

.PARAMETER PcClusterIp
PeClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.EXAMPLE
REST-Get-Pc-ACPs `
  -PcClusterIP 1.1.1.1 `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_Pc_Api.BasicHead
'30-Dec-21 21:44:13' | INFO  | Pulling all Access Control Policies
'30-Dec-21 21:44:13' | INFO  | Converting Object
'30-Dec-21 21:44:14' | INFO  | We found '20' items.

Name                           Value
----                           -----
api_version                    3.1
metadata                       {kind, length, offset, total_matches}
entities                       {@{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=}, @{status=; spec=; metadata=}…}

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  write-log -message "Pulling all Access Control Policies"

  $PsHashPayload = @{
    kind = "access_control_policy" 
    length = 50
    offset = 0
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/access_control_policies/list"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Paginate-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Create Pc Access Control Policy
##################################################################

Function REST-Create-Pc-Role-Vm-Acp {
<#
.SYNOPSIS
Retrieves the list of access control policies in Prism Central

.DESCRIPTION
V3 based API with pagination. ACPs are not visible in the UI.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER AcpName
Name of the Access Control Policy to create.

.PARAMETER AcpDescription
Description of the Access Control Policy to create.

.PARAMETER Role
The Role object pulled from. 

.EXAMPLE
REST-Update-Pc-Role-Vm-Acp `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Acp $AcpExists `
  -AcpDescription "By-BPAutonomics" `
  -Role $MyRole `
  -VmUuids $MatchingVms.metadata.uuid `
  -GroupObjs $RoleGroups
'19-Dec-21 01:04:12' | INFO  | Updating ACP 'xxxx-Linux-Operator-ACP'

status                               spec                                                                     api_version metadata
------                               ----                                                                     ----------- --------
@{state=PENDING; execution_context=} @{name=xxxx-Linux-Operator-ACP; resources=; description=By-BPAutonomics} 3.1         @{use_categories_mapping=False; kind=access_control_p…

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $AcpName,
    [parameter(mandatory)] [string] $AcpDescription,
    [parameter(mandatory)] [Object] $Role,
    [parameter(mandatory)] [Array]  $VmUuids,
    [parameter(mandatory)] [Array]  $GroupObjs
  )

  write-log -message "Creating ACP '$AcpName'"

  $PsHashPayload = @{
    spec = @{
      name = $AcpName
      description = $AcpDescription
      resources = @{
        role_reference = @{
          kind = "role"
          name = $Role.status.name
          uuid = $Role.metadata.uuid
        }
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
                  collection = "SELF_OWNED"
                }
              }
            )
            scope_filter_expression_list = @()
          }
          @{
            entity_filter_expression_list = @(
              @{
                operator = "IN"
                left_hand_side = @{
                  entity_type = "vm"
                }
                right_hand_side = @{
                  uuid_list = $VmUuids
                }
              }
            )
            scope_filter_expression_list = @()
          }
          )
        }
        user_group_reference_list = @(
        )
      }
    } 
    api_version = "3.1.0"
    metadata = @{
      kind = "access_control_policy"
      spec_version = 0
    }
  }
  Foreach ($Group in $GroupObjs){
    [array]$PsHashPayload.spec.resources.user_group_reference_list += @{
      kind = "user_group"
      name = $Group.status.resources.display_name
      uuid = $Group.metadata.uuid
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/access_control_policies"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Update Pc Access Control Policy
##################################################################

Function REST-Update-Pc-Role-Vm-Acp {
<#
.SYNOPSIS
Retrieves the list of access control policies in Prism Central

.DESCRIPTION
V3 based API with pagination. ACPs are not visible in the UI.

.PARAMETER PcClusterIp
PcClusterIp is the name or IP for the Prism Central Cluster

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER AcpName
Name of the Access Control Policy to create.

.PARAMETER AcpDescription
Description of the Access Control Policy to create.

.PARAMETER Role
The Role object pulled from. 

.EXAMPLE
REST-Update-Pc-Role-Vm-Acp `
  -PcClusterIP $MainVars.AutoDC.PcClusterIP `
  -AuthHeader $MainVars.Creds.Password_Vault.Central_PC_API.BasicHead `
  -Acp $AcpExists `
  -AcpDescription "By-BPAutonomics" `
  -Role $MyRole `
  -VmUuids $MatchingVms.metadata.uuid `
  -GroupObjs $RoleGroups
'19-Dec-21 01:04:12' | INFO  | Updating ACP 'xxxx-Linux-Operator-ACP'

status                               spec                                                                     api_version metadata
------                               ----                                                                     ----------- --------
@{state=PENDING; execution_context=} @{name=xxxx-Linux-Operator-ACP; resources=; description=By-BPAutonomics} 3.1         @{use_categories_mapping=False; kind=access_control_p…

#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIP,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [Object] $Acp,
    [parameter(mandatory)] [string] $AcpDescription,
    [parameter(mandatory)] [Object] $Role,
    [parameter(mandatory)] [Array]  $VmUuids,
    [parameter(mandatory)] [Array]  $GroupObjs
  )

  write-log -message "Updating ACP '$($Acp.spec.name)'"

  $PsHashPayload = @{
    spec = @{
      name = $Acp.spec.name
      description = $AcpDescription
      resources = @{
        role_reference = @{
          kind = "role"
          name = $Role.status.name
          uuid = $Role.metadata.uuid
        }
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
                  collection = "SELF_OWNED"
                }
              }
            )
            scope_filter_expression_list = @()
          }
          @{
            entity_filter_expression_list = @(
              @{
                operator = "IN"
                left_hand_side = @{
                  entity_type = "vm"
                }
                right_hand_side = @{
                  uuid_list = $VmUuids
                }
              }
            )
            scope_filter_expression_list = @()
          }
          )
        }
        user_group_reference_list = @(
        )
      }
    } 
    api_version = "3.1.0"
    metadata = @{
      kind = "access_control_policy"
      spec_version = $Acp.metadata.spec_version
      uuid = $Acp.metadata.uuid
    }
  }
  Foreach ($Group in $GroupObjs){
    [array]$PsHashPayload.spec.resources.user_group_reference_list += @{
      kind = "user_group"
      name = $Group.status.resources.display_name
      uuid = $Group.metadata.uuid
    }
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/access_control_policies/$($Acp.metadata.uuid)"
    Method               = "PUT"
    Body                 = $PsHashPayload
    Headers              = $AuthHeader
  }
  
  Return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
}

##################################################################
# Category-Query-V4
##################################################################

Function REST-Get-Pc-Category-V4 {
<#
.SYNOPSIS
Pulls all categories and values for the V4 API, beta.

.DESCRIPTION
Sends an entties related object in return.

.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.EXAMPLE



#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  Write-Log -message "Pulling Categories V4 API"

  
  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/prism/v4.0.a1/config/categories"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Add category to volume Group
##################################################################

Function REST-Add-Vg-Pc-Category-V4 {
<#
.SYNOPSIS
Adds a category Ext ID to a Volume group through the PC API.

.DESCRIPTION


.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ExtId 
External ID for the category to add.

.EXAMPLE

#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $ExtCatId,
    [parameter(mandatory)] [string] $ExtVgId
  )

  Write-Log -message "Pulling Categories V4 API"

  $PsHashPayload = @{
    categories = @(
      @{
        entityType = "CATEGORY"
        extId = $ExtCatId
      }
    )
  }

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/storage/v4.0.a2/config/volume-groups/$($ExtVgId)/`$actions/associate-category"
    Method      = "POST"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get V4 Volume Groups
##################################################################

Function REST-Get-VolumeGroups-V4 {
<#
.SYNOPSIS
Gets all VGs for PC V4 API

.DESCRIPTION


.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ExtId 
External ID for the category to add.

.EXAMPLE



#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  Write-Log -message "Pulling Volume Groups V4 API"


  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/storage/v4.0.a2/config/volume-groups"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get V4 Volume Groups
##################################################################

Function REST-Get-VolumeGroups-V4 {
<#
.SYNOPSIS
Gets all VGs for PC V4 API

.DESCRIPTION


.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ExtId 
External ID for the category to add.

.EXAMPLE

#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader
  )

  Write-Log -message "Pulling Volume Groups V4 API"


  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/storage/v4.0.a2/config/volume-groups"
    Method      = "GET"
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Get VG Sync Status Group Call
##################################################################

Function REST-Get-PC-VolumeGroup-Sync-V3 {
<#
.SYNOPSIS


.DESCRIPTION


.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
The name or IP for the Prism Central Cluster.

.EXAMPLE


#>
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [object] $AuthHeader
  )

  Write-Log -message "Building Cluster Query JSON - Group Method"


  $PsHashPayload = @{
    entity_type = "volume_group_config"
    group_member_attributes = $(@{
      attribute = "name"
    }
    @{
      attribute = "synchronous_replication_status"

    }
    @{
      attribute = "protection_rule_name"

    })
  }

  $RequestPayload = @{
    Uri                  = "https://$($PcClusterIp):9440/api/nutanix/v3/groups"
    Method               = "POST"
    Body                 = $PsHashPayload
    Headers     = $AuthHeader
  }

  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)

}

##################################################################
# Create VG
##################################################################

Function REST-Create-VolumeGroups-V4 {
<#
.SYNOPSIS
Gets all VGs for PC V4 API

.DESCRIPTION


.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ExtId 
External ID for the category to add.

.EXAMPLE

#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $VgName,
    [parameter(mandatory)] [string] $Sharingmode = "SHARED",
    [parameter(mandatory)] [string] $IscsiPrefix,
    [parameter(mandatory)] [string] $ClusterUuid,
    [parameter(mandatory)] [string] $Description
  )

  Write-Log -message "Creating Volume Group using V4 API"

  $PsHashPayload = @{
    name = $VgName
    sharingStatus = $Sharingmode
    iscsiTargetPrefix = $IscsiPrefix
    clusterReference = $ClusterUuid
    description = $Description
  }

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/storage/v4.0.a2/config/volume-groups"
    Method      = "POST"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 

##################################################################
# Attach VG
##################################################################

Function REST-Attach-VolumeGroups-V4 {
<#
.SYNOPSIS
Gets all VGs for PC V4 API

.DESCRIPTION


.PARAMETER AuthHeader
Authentication header for the REST API Call, e.g. @{ Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($username):$($secret)")))" }

.PARAMETER PcClusterIp 
PcCluster IP is the name or IP for the Prism Central Cluster.

.PARAMETER ExtId 

.EXAMPLE

#>  
  Param (
    [parameter(mandatory)] [string] $PcClusterIp,
    [parameter(mandatory)] [Object] $AuthHeader,
    [parameter(mandatory)] [string] $InitiatorName,
    [parameter(mandatory)] [string] $AttachmentSite,
    [parameter(mandatory)] [string] $ExtVgId
  )

  Write-Log -message "Attaching Client '$InitiatorName' VG '$ExtVgId' towards site '$AttachmentSite'"

  $PsHashPayload = @{
    iscsiInitiatorName = $InitiatorName
    attachmentSite = $AttachmentSite
  }

  $RequestPayload = @{
    Uri         = "https://$($PcClusterIp):9440/api/storage/v4.0.a3/config/volume-groups/$($ExtVgId)/`$actions/attach-iscsi-client"
    Method      = "POST"
    Body        = $PsHashPayload
    Headers     = $AuthHeader
  }
  
  return Ps-Invoke-Rest `
    -HashArguments $RequestPayload `
    -name (Get-FunctionName)
} 


Export-ModuleMember *

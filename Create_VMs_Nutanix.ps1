#region ImportPSModule
$PSPath = "\\sebaars.local\IT\Powershell\REST-API-NutanixPS\"
$PSFiles = (Get-ChildItem $PSPath -Recurse).FullName

Foreach ($PSFile in $PSFiles) {
    Import-module $PSFile
    }
#endregion ImportPSModule

#region set the basic variables
$XMLFile = "Nutanix_Infra.xml"
$PCIP = "192.168.1.100"
$PEIP = "192.168.1.101"
$Debug = 1
$LocalAdminPassword = "Y0uC@nChAngeTh!sTo€veryThing"
$DNS = @("192.168.1.5","192.168.2.5")
$Domain = "sebaars.local"
$DomainJoinCredential = Get-Credential -Message "Domain-Join Credential"
$DomainJoinUser = $DomainJoinCredential.UserName
$DomeinJoinPassword = $DomainJoinCredential.GetNetworkCredential().Password
$NutanixCredential = Get-Credential -Message "Nutanix Credential"
$Infobloxcred = Get-Credential -Message "InfoBlox account"
$InfobloxServer = "infoblox.sebaars.local"
$QADCredential = Get-Credential -Message "Quest ARS Credentials domain\account"
$QADServer = "sebaars-qa01.sebaars.local"

$NutanixUsername = $NutanixCredential.UserName
$NutanixPassword = $NutanixCredential.GetNetworkCredential().Password
$AuthHeader = @{
    Authorization = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($NutanixUsername + ":" + $NutanixPassword))
    }

[XML]$xmldocument = Get-Content -Path $XMLFile
$Servers = $xmldocument.Servers.Server
#endregion set the basic variables

ForEach ($Server in $Servers) {
    #region VarVM
    $VMName = $Server.Name
    $ClusterName = $Server.Cluster
    $CPU = $Server.CPU
    $RAM = $Server.RAM -as [int]
    $IP = $Server.IP
    $Gateway = $Server.Gateway
    $NetMask = $Server.Netmask
    $SubnetNames = $Server.SubnetNames.SubnetName
    $Disks = $Server.Disks
    $ContainerName = "VDI-Acceptatie-Infra-DEV-Infra-01"
    $ImageName = $Server.ImageName
    $ProjectName = "Default"
    $DiskSizeGB = 72
    $DiskSizeMB = $DiskSizeGB*1024
    $RAMMB = $RAM*1024
    $OU = $Server.OU
    #endregion VarVM

    $VMExist = ((REST-Get-Pe-VMs-V1 -PeClusterIP $PEIP -AuthHeader $AuthHeader).entities | Where-Object {$_.VmName -eq $VmName})

    If ($VMExist.vmName -eq $VMName) {
        Write-Log -Message "Server $VMName already exist, skipping this one."
    }
        #region SplitDNSServers
                $dns1 = $DNS.split(",")[0]
                $dns2 = $DNS.split(",")[1]
        #endregion SplitDNSServers
        write-log -message "Server $VMName doesn't exist, making $VMName"
        Write-Log -Message "Collecting all the information for the $VMName"
        
        #region InfraInfoVM
        $Cluster = ((REST-Get-PC-Clusters-V3 -PcClusterIp $PCIP -AuthHeader $AuthHeader).Entities | Where-Object {$_.Status.Name -eq $Clustername})
        $ClusterUUID = ((REST-Get-Pc-Clusters-V3 -PcClusterIp $PCIP -AuthHeader $AuthHeader).Entities | Where-Object {$_.status.name -eq $ClusterName}).metadata.uuid
        $AOSVersion = $Cluster.status.resources.config.build.version
        $ContainerUUID = ((REST-Get-Pe-Containers -PeClusterIp $PEIP -AuthHeader $AuthHeader).entities | Where-Object {$_.name -eq $ContainerName}).containeruuid
        $Subnetname = ($Server.SubnetNames.SubnetName | Where-Object {$_.Primary -eq "True"}).Name
        $SubnetUUID = ((REST-Get-Pe-Networks -PeClusterIp $PEIP -AuthHeader $AuthHeader).Entities | Where-Object {$_.Name -eq $Subnetname}).uuid
        $ImageUUID = ((REST-List-Px-Images -PxClusterIP $PEIP -AuthHeader $AuthHeader).Entities | Where-object {$_.Status.Name -eq $Imagename}).metadata.uuid
        $ProjectUUID = ((REST-Query-Pc-Projects -PcClusterIP $PCIP -AuthHeader $AuthHeader).Entities | Where-Object {$_.Status.Name -eq $ProjectName}).metadata.uuid
        $OwnerName = $NutanixUsername
        $OwnerUUID = ((REST-Get-PC-Users -PcClusterIp $PCIP -AuthHeader $AuthHeader).entities | Where-Object {$_.Status.Name -eq $OwnerName}).metadata.uuid
        Write-Log -Message "All the information is collected for $VMName"
        #endregion InfraInfoVM

        #region SysPrepInfo
        Write-Log -message "Collection SysPrep information for $VMName"
        $SysPrepInfo = LIB-IP-Domain-Server-SysprepXML -VMName $VMName -LocalAdminPass $LocalAdminPassword -IFName "Ethernet" -IPAddress $IP -NetMask $NetMask -Gateway $Gateway -DNS1 $DNS1 -DNS2 $DNS2 -Domain $Domain -DomainJoinUser $DomainJoinUser -DomainJoinPassword $DomeinJoinPassword
        Write-Log -message "All the information is collected for SysPrep for $VMName"
        #endregion SysPrepInfo

        #region CreateVM
        Write-Log -Message "$VMName will be created on $ClusterName"
        REST-Create-Pc-Vm-V3 -PcClusterIp $PCIP -AuthHeader $AuthHeader -CpuSockets 1 -CpuThreads 1 -CpusPerSocket $CPU -MemoryMB $RAMMB -VmName $VmName -DiskMB $DiskSizeMB -BootMode 2 -ImageUuid $ImageUUID -DisableCdRom $True -DiskType SCSI -ContainerName $ContainerName -ContainerUuid $ContainerUUID -SubnetName $Subnetname -SubnetUuid $SubnetUUID -ClusterName $ClusterName -ClusterUuid $ClusterUUID -ProjectName Default -GuestOSCustomizeScript $SysPrepInfo -GuestOSType Windows -GpuProfileVendor none -GpuProfileDeviceType none -GpuProfileDeviceId none -GpuProfileDeviceName none -AosVersion $AOSVersion -ProjectUuid $ProjectUUID -OwnerName $OwnerName -OwnerUuid $OwnerUUID
        Write-Log -Message "$VMName is created on $ClusterName"
        #endregion CreateVM

        #region 10 sec Sleep
        Write-Log -Message "10 seconde sleep, have a little bit of patience"
            Start-Sleep -Seconds 10
        Write-Log -Message "oke... sometimes 10 secondes is taking a long time "
        #endregion 10 sec Sleep

        #region CreateDisk
        If ($Disks -eq [System.String]::IsNullOrEmpty($Disks))  {
            Write-Log -Message "No additionals disk configured, doing nothing"
            }
        Else {
            Foreach ($Disk in $Disks.DiskSize) {
            Write-Log -Message "Additional Disks configured, gathering the specs."
            $VMUUID = ((REST-Get-Pe-VMs-V1 -PeClusterIP $PEIP -AuthHeader $AuthHeader).entities | Where-Object {$_.VmName -eq $VmName}).uuid
            $VMInfo = REST-Get-Px-VM-V2-Detail -PeClusterIP $PEIP -AuthHeader $AuthHeader -VmUuid $VMuuid
            Write-Log -Message "Specs are collected, preparing the Disks "
        
            Write-Log -Message "Creating the Disk with size $Disk GB for $VMName"
                REST-Add-Pe-VmDisk -PeClusterIP $PEIP -AuthHeader $AuthHeader -VmDetailObj $Vminfo -SizeGb $Disk -DiskType SCSI
                    }
            Write-Log -Message "Disk with size $Disk GB configured for $VMname"
        }
        #endregion CreateDisk
        
        #region InfobloxDNSregistratie
        # Ignore SSL cert Exception
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $data = "{
                        ""name"": ""$Name.$Domain"",
                        ""ipv4addrs"": [
                            {
                                ""ipv4addr"":""$IP""
           
                            }
                        ]
                    }"


        $baseUri = "https://$InfobloxServer/wapi/v2.10.5"
        $uri = "$baseUri/record:host"
    
        Invoke-RestMethod -Uri $uri -Method POST -Credential $Infobloxcred -ContentType "application/json" -Body $data -Verbose
        #endregion InfobloxDNSregistratie

        #region AddAddionalsNICs
        $AddSubNetnames = ($Server.SubnetNames.SubnetName | Where-Object {$_.Primary -eq "False"}).Name
        If ($AddSubNetnames -eq [System.String]::IsNullOrEmpty($Disks))  {
            Write-Log -Message "Geen HardDisk gezet, wordt niet aangemaakt"
            }
        Else {
            Foreach ($AddSubNetname in $AddSubNetnames){ 
                $VMs = REST-Get-Px-VMs-V3 -PxClusterIP $PCIP -AuthHeader $AuthHeader
                $VMUUID = ((REST-Get-Px-VMs-V3 -PxClusterIP $PCIP -AuthHeader $AuthHeader).entities | Where-Object {$_.Status.name -eq $VmName}).metadata.uuid
                $VM = $VMs.entities | Where-Object {$_.MetaData.uuid -eq $VMUUID}
                $AddSubnetUUID = ((REST-Get-Pe-Networks -PEClusterIp $PEIP -AuthHeader $AuthHeader).entities | Where-Object {$_.name -eq $AddSubnetName}).uuid
                $UUID = (new-guid).guid
                $Nic = @"
                {
                "subnet_reference": {
                "kind": "subnet",
                "uuid": "$($AddSubnetUUID)"
                },
                "is_connected": true,
                "uuid": "$UUID"
                }
"@
                $nicobj = $nic | convertfrom-json
                [array]$VM.spec.resources.nic_list += $nicobj
                REST-Update-Px-VMs-V3-Object -PxClusterIp $PCIP -AuthHeader $AuthHeader -VM $VM
            }
        }
        #endregion AddAddionalsNICs

        #region StartVM
        Write-Log -message "Powering on $VMname"
        REST-Set-Pe-VM-PowerState -PeClusterIP $PEIP -AuthHeader $AuthHeader -VmUuid $VMUUID -State On
        Write-Log -message "$VMname is Powered on"
        #endregion StartVM

        #region 120 sec Sleep
        Write-Log -Message "120 seconde sleep, have a little bit of patience"
            Start-Sleep -Seconds 120
        Write-Log -Message "oke... sometimes 120 secondes is taking a long time "
        #endregion 120 sec Sleep

        #region Move Computer-Account to OU.
        $QADUsername = $QADCredential.UserName
        $QADPassword = $QADCredential.Password
        Write-Log -Message "Making a connection with the QAD Servers in $Domain "
        Connect-QADService -Proxy -Service $QADServer -ConnectionAccount $QADUsername -ConnectionPassword $QADPassword
        Write-Log -Message "Connection is made with the QAD Servers in $Domain "

        Start-Sleep -Seconds 10

        Write-Log -Message "Move $VMName to $OU"
        $ComputerAccountExists = Get-QADComputer $VMName
        Write-Log -Message "Check of $VMName in $Domain already exist."
        If ($Null -ne $ComputerAccountExists) {
            $CheckOU = $ComputerAccountExists.ParentContainer
            If ($CheckOU -ne $OU) {
                Write-Log -message "$VMName already exist, moving it to $OU"
                Get-QADComputer $VMName | Move-QADObject -to $OU
                Write-Log -message "$VMName is moved to $OU"
            }
            Else {
                Write-Log -message "$OU doesn't exist, $VMName can't be moved. Somebody made a boeboe..."
            }
        Else {
            Write-Log -Message "$VMName doesn't exist in $Domain, something is going wrong.... RED ALERT!!!!!!"
            }
        Write-Log -message "disconnecting the connection with QAD"
        Disconnect-QADService
        Write-Log -message "The connection with QAD is disconnected"
        #endregion Move Computer-Account to OU.
        }
    }

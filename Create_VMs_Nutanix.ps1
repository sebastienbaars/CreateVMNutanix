#region ImportPSModule
$PSPath = "\\sebaars.local\IT\Powershell\Function-Library\"
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
$DNSDC1 = @("192.168.1.5","192.168.2.5")
$DNSDC2 = @("192.168.2.5","192.168.3.5")
$DNSDC3 = @("192.168.3.5","192.168.1.5")
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
    $Template = $Server.Template
    $CPU = $Server.CPU
    $RAM = $Server.RAM -as [int]
    $IP = $Server.IP
    $Gateway = $Server.Gateway
    $NetMask = $Server.Netmask
    $SubnetName = $Server.SubnetName
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
        Write-Log -Message "Server $VMName bestaat al, deze wordt niet aangemaakt" -ForegroundColor Yellow
    }
        #region DNSSettings
        Else{
            If ($VMName -like "***1*") {
                write-log -message "$VMName komt in DC1, DNS settings van DC1 worden gebruikt"
                $dns1 = $DNSDC1.split(",")[0]
                $dns2 = $DNSDC1.split(",")[1]
            }
            ElseIf ($VMName -like "***2*") {
                write-log -message "$VMName komt in DC2, DNS settings van DC2 worden gebruikt"
                $dns1 = $DNSDC2.split(",")[0]
                $dns2 = $DNSDC2.split(",")[1]
            }
            ElseIf ($VMName -like "***3*") {
                write-log -message "$VMName komt in DC3, DNS settings van DC3 worden gebruikt"
                $dns1 = $DNSDC3.split(",")[0]
                $dns2 = $DNSDC3.split(",")[1]
            }  
            Else {
                write-log -message "stomme template doen wij lekker niks mee"
            }
        #endregion DNSSettings
        write-log -message "Server $VMName bestaat niet, deze wordt nu aangemaakt"
        Write-Log -Message "Parameters worden verzameld voor het maken van $VMName"
        
        #region InfraInfoVM
        $Cluster = ((REST-Get-PC-Clusters-V3 -PcClusterIp $PCIP -AuthHeader $AuthHeader).Entities | Where-Object {$_.Status.Name -eq $Clustername})
        $ClusterUUID = ((REST-Get-Pc-Clusters-V3 -PcClusterIp $PCIP -AuthHeader $AuthHeader).Entities | Where-Object {$_.status.name -eq $ClusterName}).metadata.uuid
        $AOSVersion = $Cluster.status.resources.config.build.version
        $ContainerUUID = ((REST-Get-Pe-Containers -PeClusterIp $PEIP -AuthHeader $AuthHeader).entities | Where-Object {$_.name -eq $ContainerName}).containeruuid
        $SubnetUUID = ((REST-Get-Pe-Networks -PeClusterIp $PEIP -AuthHeader $AuthHeader).Entities | Where-Object {$_.Name -eq $Subnetname}).uuid
        $ImageUUID = ((REST-List-Px-Images -PxClusterIP $PEIP -AuthHeader $AuthHeader).Entities | Where-object {$_.Status.Name -eq $Imagename}).metadata.uuid
        $ProjectUUID = ((REST-Query-Pc-Projects -PcClusterIP $PCIP -AuthHeader $AuthHeader).Entities | Where-Object {$_.Status.Name -eq $ProjectName}).metadata.uuid
        $OwnerName = $NutanixUsername
        $OwnerUUID = ((REST-Get-PC-Users -PcClusterIp $PCIP -AuthHeader $AuthHeader).entities | Where-Object {$_.Status.Name -eq $OwnerName}).metadata.uuid
        Write-Log -Message "Parameters zijn verzameld voor het maken van $VMName"
        #endregion InfraInfoVM

        #region SysPrepInfo
        Write-Log -message "SysPrep gegevens worden verzameld voor $VMName"
        $SysPrepInfo = LIB-IP-Domain-Server-SysprepXML -VMName $VMName -LocalAdminPass $LocalAdminPassword -IFName "Ethernet" -IPAddress $IP -NetMask $NetMask -Gateway $Gateway -DNS1 $DNS1 -DNS2 $DNS2 -Domain $Domain -DomainJoinUser $DomainJoinUser -DomainJoinPassword $DomeinJoinPassword
        Write-Log -message "SysPrep gegevens zijn verzameld voor $VMName"
        #endregion SysPrepInfo

        #region CreateVM
        Write-Log -Message "De $VMName wordt nu aangemaakt"
        REST-Create-Pc-Vm-V3 -PcClusterIp $PCIP -AuthHeader $AuthHeader -CpuSockets 1 -CpuThreads 1 -CpusPerSocket $CPU -MemoryMB $RAMMB -VmName $VmName -DiskMB $DiskSizeMB -BootMode 2 -ImageUuid $ImageUUID -DisableCdRom $True -DiskType SCSI -ContainerName $ContainerName -ContainerUuid $ContainerUUID -SubnetName $Subnetname -SubnetUuid $SubnetUUID -ClusterName $ClusterName -ClusterUuid $ClusterUUID -ProjectName Default -GuestOSCustomizeScript $SysPrepInfo -GuestOSType Windows -GpuProfileVendor none -GpuProfileDeviceType none -GpuProfileDeviceId none -GpuProfileDeviceName none -AosVersion $AOSVersion -ProjectUuid $ProjectUUID -OwnerName $OwnerName -OwnerUuid $OwnerUUID
        Write-Log -Message "De $VMName is aangemaakt"
        #endregion CreateVM

        #region 10 sec Sleep
        Write-Log -Message "10 seconde geduld hebben "
            sleep -Seconds 10
        Write-Log -Message "pff soms duurt zelfs 10 secondes heel lang.... "
        #endregion 10 sec Sleep

        #region CreateDisk
        If ($Disks -eq [System.String]::IsNullOrEmpty($Disks))  {
            Write-Log -Message "Geen HardDisk gezet, wordt niet aangemaakt"
            }
        Else {
            Foreach ($Disk in $Disks.DiskSize) {
            Write-Log -Message "Gegevens ophalen voor het aanmaken van de HardDisks "
            $VMUUID = ((REST-Get-Pe-VMs-V1 -PeClusterIP $PEIP -AuthHeader $AuthHeader).entities | Where-Object {$_.VmName -eq $VmName}).uuid
            $VMInfo = REST-Get-Px-VM-V2-Detail -PeClusterIP $PEIP -AuthHeader $AuthHeader -VmUuid $VMuuid
            Write-Log -Message "Gegevens zijn opgehaald voor het aanmaken van de HardDisks "
        
            Write-Log -Message "Aanmaken van de HardDisks"
            Write-Log -Message "D-schijf wordt aangemaakt voor $VMName, als deze is gezet"

                REST-Add-Pe-VmDisk -PeClusterIP $PEIP -AuthHeader $AuthHeader -VmDetailObj $Vminfo -SizeGb $Disk -DiskType SCSI

                    }
            Write-Log -Message "HardDisks zijn aangemaakt "
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


        #region StartVM
        Write-Log -message " $VMname wordt gestart "
        REST-Set-Pe-VM-PowerState -PeClusterIP $PEIP -AuthHeader $AuthHeader -VmUuid $VMUUID -State On
        Write-Log -message " $VMname is gestart "
        #endregion StartVM

        #region 120 sec Sleep
        Write-Log -Message "120 seconde geduld hebben "
            sleep -Seconds 120
        Write-Log -Message "pff soms duurt zelfs 120 secondes heel lang.... "
        #endregion 120 sec Sleep

        #region Move Computer-Account to OU.
        $QADUsername = $QADCredential.UserName
        $QADPassword = $QADCredential.Password
        Write-Log -Message "Connectie maken naar de QAD Servers in $Domain "
        Connect-QADService -Proxy -Service $QADServer -ConnectionAccount $QADUsername -ConnectionPassword $QADPassword
        Write-Log -Message "Connectie gemaakt naar de QAD Servers in $Domain "

        Sleep -Seconds 10

        Write-Log -Message "Move $VMName naar $OU"
        $ComputerAccountExists = Get-QADComputer $VMName
        Write-Log -Message "Check of $VMName in $Domain bestaat."
        If ($ComputerAccountExists -ne $Null) {
            $CheckOU = $ComputerAccountExists.ParentContainer
            If ($CheckOU -ne $OU) {
                Write-Log -message "$VMName bestaat en wordt nu verhuisd naar $OU"
                Get-QADComputer $VMName | Move-QADObject -to $OU
                Write-Log -message "$VMName is verhuisd naar $OU"
            }
            Else {
                Write-Log -message "$OU bestaat niet, $VMName kan niet worden verhuisd."
            }
        Else {
            Write-Log -Message "$VMName bestaat niet in het $Domain"
            }
        Write-Log -message "Verbreek de verbinding met QAD"
        Disconnect-QADService
        Write-Log -message "Verbinding met QAD is verbroken"
        #endregion Move Computer-Account to OU.
        }
    }
}

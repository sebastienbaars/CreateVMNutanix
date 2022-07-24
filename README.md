# CreateVMNutanix
Creating VM's with Powershell on Nutanix AHV
<!-- wp:paragraph -->
<p>For creating multiple VM's on Nutanix quickly with the correct storage pool and network. I created a Powershell script with the Powershell Modules of Michell Grauwmans thats created the VM's, attached the Disks that you want and domain join the Windows Server with SysPrep. The customer that I created this script for, is using Infoblox for IPAM and QuestARS for delagadedRights on ActiveDirectory.  I'm doing this with a Image disk where Windows Server is already installed in and is configured for SysPrep. At the moment I'm not explaining how to create that Image.  </p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>For the VM spec's I'm using an XML file as source. The XML entries explain there self, but with the &lt;Disks> entry you can configure the disk that you wan't to add is size. So now there will be configured a 20GB additional disk. If you add a <strong>&lt;Disksize>50&lt;/DiskSize></strong> to the &lt;Disks> entry there will by added a third disk with the size of 50GB. You can add as many diskes that you want. The sample below is of a SQL-Server in a Citrix deployment. </p>
<!-- /wp:paragraph -->

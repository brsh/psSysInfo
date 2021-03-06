﻿##
## Leveragd from 
## http://www.the-little-things.net/blog/2015/10/03/powershell-thoughts-on-module-design/
##
#region Private Variables
# Current script path
[string]$ScriptPath = Split-Path (get-variable myinvocation -scope script).value.Mycommand.Definition -Parent
#endregion Private Variables
 
#region Methods
 
# Dot sourcing private script files
Get-ChildItem $ScriptPath/private -Recurse -Filter "*.ps1" -File | Foreach { 
    . $_.FullName
}
 
# Load and export methods


## Function to pull OS information (which version, edition, install time, etc.)
function Get-OSInfo {
    <# 
    .SYNOPSIS 
        OS info via WMI
         
    .DESCRIPTION 
        This function pulls the following information from WMI: 
            Computername
            SystemType (workstation, server, or domain controller)
            RegisteredUser
            Organization
            Description
            OSFullName (the entire description, including edition)
            OS (the simple version)
            Edition
            Version
            BuildNumber
            ServicePack (if one is installed, that is)
            Architecture (32 or 64 bit - at this point)
            InstallDate 
            LastBoot
            WinToGo
 
    .PARAMETER  ComputerName 
        The name of the computer to query (localhost is default)
 
    .EXAMPLE 
        PS C:\> Get-OSInfo 
         
    .EXAMPLE 
        PS C:\> Get-OSInfo -ComputerName MyVM
     
    .EXAMPLE 
        PS C:\> Get-OSInfo MyVM 
 
    .INPUTS 
        System.String 
 
    #> 
    Param (
        [Parameter(Position=0)]
        [string] $hostname="localhost"     
    )

    Get-WmiObject win32_operatingsystem -ComputerName $hostname | `
        ForEach-Object {
            switch ($_.ProductType) {
                1 { $b = "Workstation " }
                2 { $b = "Domain Controller" }
                3 { $b = "Server" }
                default { $b = "Unknown" }
            }
            switch ($_.OperatingSystemSKU) {
                1 { $a = "Ultimate" }
                2 { $a = "Home Basic" }
                3 { $a = "Home Premium" }
                4 { $a = "Enterprise" }
                5 { $a = "Home Basic N" }
                6 { $a = "Business" }
                7 { $a = "Standard Server" }
                8 { $a = "Datacenter Server" }
                9 { $a = "Small Business Server" }
                10 { $a = "Enterprise Server" }
                11 { $a = "Started" }
                12 { $a = "Datacenter Server Core" }
                13 { $a = "Standard Server Core" }
                14 { $a = "Enterprise Server Core" }
                15 { $a = "Enterprise Server Itanium" }
                16 { $a = "Business N" }
                17 { $a = "Web Server" }
                18 { $a = "Cluster Server" }
                19 { $a = "Home Server" }
                20 { $a = "Storage Express Server" }
                21 { $a = "Storage Standard Server" }
                22 { $a = "Storage Workgroup Server" }
                23 { $a = "Storage Enterprise Server" }
                24 { $a = "Server For Small Business" }
                25 { $a = "Small Business Server Premium" }
                26 { $a = "TBD" }
                default { $a = "Undefined" }
            }
            $osNamen = $_.Caption
            $osNamen = $osNamen.Replace("Microsoft ", "")
            $osNamen = $osNamen.Replace($a, "")
            $osNamen = $osNamen.Replace("Edition", "")
            $InfoHash =  @{
                Computername = $_.CSName
                OS = $osNamen.Trim()
                OSFullName = $_.Caption
                ServicePack = $_.CSDVersion
                Architecture = $_.OSArchitecture
                Description = $_.Description
                Organization = $_.Organization
                BuildNumber = $_.BuildNumber
                InstallDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate)
                LastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.LastBootUpTime)
                WinToGo = $_.PortableOperatingSystem
                SystemType = $b.Trim()
                RegisteredUser = $_.RegisteredUser
                Version = $_.Version
                Edition = $a.Trim()
            }
            $InfoStack = New-Object -TypeName PSObject -Property $InfoHash

            #Add a (hopefully) unique object type name
            $InfoStack.PSTypeNames.Insert(0,"OS.Information")

            #Sets the "default properties" when outputting the variable... but really for setting the order
            $defaultProperties = @('Computername', 'SystemType', 'RegisteredUser', 'Organization', 'Description', 'OSFullName', 'OS', 'Edition', 'Version', 'BuildNumber', 'ServicePack', 'Architecture', 'InstallDate', 'LastBoot', 'WinToGo')
            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
            $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
            $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers

            $InfoStack
        }
}

new-alias -name gosi -value Get-OSInfo -Description "Get info on the OS version" -Force

 
## Boot Times!
function Get-LastBootTime { 
    <# 
    .SYNOPSIS 
        Local machine last brought online
 
    .DESCRIPTION 
        This function pulls the date when the local machine was last brought online. It really only runs the Get-OSInfo function and returns the lastboot param.
 
    .EXAMPLE 
        PS C:\> Get-LastBootTime

    .INPUTS 
        None 
    #> 
    (Get-OSInfo).LastBoot
}

function Get-Uptime {
<#
    .SYNOPSIS
    Timespan that the computer has been running
    .DESCRIPTION
    This returns a timespan for how long the specified computer has been up and running. As a timespan, serveral formatting options are available (like (get-uptime).TotalDays and (get-uptime) -f {0})
    .PARAMETER HostName
    Defaults to current
    .EXAMPLE
    PS C:\> Get-Uptime
    .EXAMPLE
    PS C:\> (Get-Uptime).TotalDays
    .EXAMPLE
    PS C:\> (Get-Uptime).ToString()
    .OUTPUTS
    TimeSpan
#>
    param ( 
        [Parameter(Position=0)]
        [string] $hostname="localhost"   
    )
    New-TimeSpan -start (Get-LastBootTime $hostname) -end $(get-date)
}

New-Alias -name uptime -Value Get-Uptime -Description "How long the computer has been running" -force

function Get-LastBootTimes([int] $count = 6) {
    <# 
    .SYNOPSIS 
       Recent on-/off-line times
 
    .DESCRIPTION 
        This function pulls the dates of the last few boots (both ups and downs). It queries the event log for startups, shutdowns, and reboots. The count can be set for how many boots to list (default is 6).

    .PARAMETER Count
        How many boot items to list
 
    .EXAMPLE 
        PS C:\> Get-LastBootTimes

    .EXAMPLE 
        PS C:\> Get-LastBootTimes 20

    .EXAMPLE 
        PS C:\> Get-LastBootTimes -count 20


    .EXAMPLE 
        PS C:\> Get-LatBootTimes | Sort-Object TimeGenerated

    .INPUTS 
        System.Int32
    #>
    $a = Get-EventLog System | Where-Object EventID -eq 6009 | Select-Object TimeGenerated -First $count | add-member -MemberType NoteProperty -Name Action -value "Startup" -passthru
    $a += Get-EventLog System | Where-Object EventID -eq 6006 | Select-Object TimeGenerated -First $count | add-member -MemberType NoteProperty -Name Action -value "Shutdown" -passthru
    $a += Get-EventLog System | Where-Object EventID -eq 6008 | Select-Object TimeGenerated -First $count | add-member -MemberType NoteProperty -Name Action -value "Unexpected" -passthru
    $a  # | Sort-Object TimeGenerated | Select-Object -Last $count | Format-Table Action,TimeGenerated -AutoSize
}

New-Alias -Name glbt -value Get-LastBootTime -Description "Get the last boot times" -Force
New-Alias -name glbts -Value Get-LastBootTimes -Description "Get the last x boot times" -force

## System information
function Get-SysInfo {
    <# 
    .SYNOPSIS 
        System info via WMI
 
    .DESCRIPTION 
        This function pulls the following information from WMI: 
            Computername
            CurrentUser
            OwnerName
            DNSName
            Domain
            DomainRole
            Manufacturer
            Model
            IsVirtual
            BootStatus
            SystemType
            ProcessorsLogical
            ProcessorsPhysical
 
    .PARAMETER  ComputerName 
        The name of the computer to query (localhost is default)
 
    .EXAMPLE 
        PS C:\> Get-SysInfo 
         
    .EXAMPLE 
        PS C:\> Get-SysInfo -ComputerName MyVM
     
    .EXAMPLE 
        PS C:\> Get-SysInfo MyVM 
 
    .INPUTS 
        System.String 
 
    #> 
    Param (
        [Parameter(Position=0)]
        [string] $hostname="localhost"     
    )
    Get-WmiObject -Class win32_Computersystem -ComputerName $hostname | `
        ForEach-Object {
            switch ($_.DomainRole) {
                0 { $dr = "Standalone Workstation" }
                1 { $dr = "Member Workstation" }
                2 { $dr = "Standalone Server" }
                3 { $dr = "Member Server" }
                4 { $dr = "Backup Domain Controller" }
                5 { $dr = "Primary Domain Controller" }
                Default { $dr = "Unknown"}
            }
            $InfoHash =  @{
                Computername = $_.PSComputerName
                DNSName = $_.DNSHostName
                Domain = $_.Domain
                DomainRole = $dr.Trim()
                BootStatus = $_.BootupState
                Manufacturer = $_.Manufacturer
                Model = $_.Model
                IsVirtual = $_.HypervisorPresent
                ProcessorsLogical = $_.NumberOfLogicalProcessors
                ProcessorsPhysical = $_.NumberOfProcessors
                OwnerName = $_.PrimaryOwnerName
                SystemType = $_.SystemType
                CurrentUser = $_.UserName
            }
            $InfoStack = New-Object -TypeName PSObject -Property $InfoHash

        #Add a (hopefully) unique object type name
        $InfoStack.PSTypeNames.Insert(0,"Sys.Information")

        #Sets the "default properties" when outputting the variable... but really for setting the order
        $defaultProperties = @('Computername', 'CurrentUser', 'OwnerName', 'DNSName', 'Domain', 'DomainRole', 'Manufacturer', 'Model', 'IsVirtual', 'BootStatus', 'SystemType', 'ProcessorsPhysical', 'ProcessorsLogical')
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
        $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers

        $InfoStack
    }
}

New-Alias -name gsysi -Value Get-SysInfo -Description "Get system information" -force

##Processor info
function Get-ProcessorInfo {
    <# 
    .SYNOPSIS 
        Processor info via WMI
 
    .DESCRIPTION 
        This function pulls the following information from WMI: 
            Computername
            Name
            Description
            Manufacturer
            Bitness
            AssetTag
            CurrentLoad
            CurrentVoltage
            CurrentMhz
            MaxMhz
            Cores
            LogicalProcessors
            HyperThreaded
            VTEnabled
 
    .PARAMETER  ComputerName 
        The name of the computer to query (localhost is default)
 
    .EXAMPLE 
        PS C:\> Get-ProcessorInfo 
         
    .EXAMPLE 
        PS C:\> Get-ProcessorInfo -ComputerName MyVM
     
    .EXAMPLE 
        PS C:\> Get-ProcessorInfo MyVM 
 
    .INPUTS 
        System.String 
 
    #> 
    Param (
        [Parameter(Position=0)]
        [string] $hostname="localhost"     
    )
    Get-WmiObject -Class win32_Processor -ComputerName $hostname | `
        ForEach-Object {
            switch ($_.Architecture) {
                0 { $arch = "x86" }
                1 { $arch = "MIPS" }
                2 { $arch = "Alpha" }
                3 { $arch = "PowerPC" }
                4 { $arch = "ia64" }
                9 { $arch = "x64" }
                Default { $arch = "Unknown" }
            }
            $namen = $_.Name
            $namen = $namen.replace("(R)", "")
            $namen = $namen.replace("(C)", "")
            $namen = $namen.replace("(TM)", "")
            $InfoHash =  @{
                Computername = $_.PSComputerName
                Bitness = $_.AddressWidth
                AssetTag = $_.AssetTag
                Description = $_.Description
                CurrentMhz = $_.CurrentClockSpeed
                CurrentVoltage = ($_.CurrentVoltage / 10)
                CurrentLoad = $_.LoadPercentage
                Manufacturer = $_.Manufacturer
                MaxMhz = $_.MaxClockSpeed
                Name = $namen
                Cores = $_.NumberOfCores
                LogicalProcessors = $_.NumberOfLogicalProcessors
                HyperThreaded = ($_.NumberOfCores -lt $_.NumberOfLogicalProcessors)
                VTEnabled = $_.VirtualizationFirmwareEnabled
            }
            $InfoStack = New-Object -TypeName PSObject -Property $InfoHash
            #Add a (hopefully) unique object type name
            $InfoStack.PSTypeNames.Insert(0,"CPU.Information")

            #Sets the "default properties" when outputting the variable... but really for setting the order
            $defaultProperties = @('Computername', 'Name', 'Description', 'Manufacturer', 'Bitness', 'AssetTag', 'CurrentLoad', 'CurrentVoltage', 'CurrentMhz', 'MaxMhz', 'Cores', 'LogicalProcessors', 'HyperThreaded', 'VTEnabled')
            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
            $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
            $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers

            $InfoStack
        }
}

New-Alias -name gproc -Value Get-ProcessorInfo -Description "Get processor information" -force

function Get-Battery {
    <# 
    .SYNOPSIS 
        Battery info via WMI
 
    .DESCRIPTION 
        This function pulls the following information from WMI: 
            Computername
            Name
            Description
            BatteryStatus (in numeric form)
            BatteryStatusText (full text)
            BatteryStatusChar (2 char abrev)
            Health
            EstimatedChargeRemaining
            RunTimeMinutes (lots of minutes)
            RunTime (human readable)
            RunTimeSpan (easily translatable)

        Note: This function is used in the prompt
 
    .PARAMETER  ComputerName 
        The name of the computer to query (localhost is default)
 
    .EXAMPLE 
        PS C:\> Get-Battery 
         
    .EXAMPLE 
        PS C:\> Get-Battery -ComputerName MyVM
     
    .EXAMPLE 
        PS C:\> Get-Battery MyVM 
 
    .INPUTS 
        System.String 
 
    #> 
    Param (
        [Parameter(Position=0)]
        [string] $hostname="localhost"     
    )
    Get-WmiObject -Class win32_Battery -ComputerName $hostname | `
        ForEach-Object {
            switch ($_.BatteryStatus) {
                1 { $textstat = "Discharging"; $charstat = "--"; break }
                2 { $textstat = "On AC"; $charstat = "AC"; break } #Actually AC
                3 { $textstat = "Charged"; $charstat = "=="; break }
                4 { $textstat = "Low"; $charstat = "__"; break }
                5 { $textstat = "Critical"; $charstat = "!!"; break }
                6 { $textstat = "Charging"; $charstat = "++"; break }
                7 { $textstat = "Charging/High"; $charstat = "++"; break }
                8 { $textstat = "Charging/Low"; $charstat = "+_"; break }
                9 { $textstat = "Charging/Critical"; $charstat = "+!"; break }
                10 { $textstat = "Undefined"; $charstat = "??"; break }
                11 { $textstat = "Partially Charged"; $charstat = "//"; break }
                Default { $textstat = "Unknown"; $charstat = "??"; break }
            }
            $ts = New-TimeSpan -Minutes $_.EstimatedRunTime
            $InfoHash =  @{
                Computername = $_.PSComputerName
                BatteryStatus = $_.BatteryStatus
                BatteryStatusText = $textstat
                BatteryStatusChar = $charstat
                Name = $_.Name
                Description = $_.Description
                EstimatedChargeRemaining = $_.EstimatedChargeRemaining
                RunTimeMinutes = $_.EstimatedRunTime
                RunTime = '{0:00}h {1:00}m' -f $ts.Hours,$ts.Minutes
                RunTimeSpan = $ts
                Health = $_.Status
            }
            $InfoStack = New-Object -TypeName PSObject -Property $InfoHash
            
            #Add a (hopefully) unique object type name
            $InfoStack.PSTypeNames.Insert(0,"CPU.Information")

            #Sets the "default properties" when outputting the variable... but really for setting the order
            $defaultProperties = @('Computername', 'Name', 'Description', 'BatteryStatus', 'BatteryStatusText', 'BatteryStatusChar', 'Health', 'EstimatedChargeRemaining', 'RunTimeMinutes', 'RunTime', 'RunTimeSpan')
            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
            $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
            $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers

            $InfoStack
        }
}

New-Alias -name gbatt -Value Get-Battery -Description "Get battery information" -force

## Volume info
function Get-Volume {
    <# 
    .SYNOPSIS 
        Disk volume info via WMI
 
    .DESCRIPTION 
        This function pulls the following information from WMI: 
            Drive
            Label
            Type
            Format
            PageFile (if it's located on this volume)
            Compressed
            BootDrive
            SystemDrive
            FreeGB
            TotalGB
 
    .PARAMETER  ComputerName 
        The name of the computer to query (localhost is default)
 
    .EXAMPLE 
        PS C:\> Get-Volume 
         
    .EXAMPLE 
        PS C:\> Get-Volume -ComputerName MyVM
     
    .EXAMPLE 
        PS C:\> Get-Volume MyVM 
 
    .INPUTS 
        System.String 
 
    #> 
    Param (
        [string] $hostname="localhost",
        [string] $type = "All"
    )

    Switch -Wildcard ($type) {
        "R*" { $WMIFilter = "DriveType='2'"; break }
        "L*" { $WMIFilter = "DriveType='3'"; "Hello"; break }
        "N*" { $WMIFilter = "DriveType='4'"; break }
        Default { $WMIFilter = "DriveType='2' or DriveType='3' or DriveType='4'"; break }
    }
    Get-WmiObject -Class Win32_LogicalDisk -ComputerName $hostname -Filter "$WMIFilter" | ForEach-Object {

        $pagefile = $false
        $bootdrive = $false
        $systemdrive = $false

        try {            
            if ($_.DriveType -eq "3") {
                $driveletter = $_.DeviceID
                $hold = Get-WmiObject Win32_Volume -Filter "DriveLetter='$driveletter'"
                $pagefile = $hold.PageFilePresent
                $bootdrive = $hold.BootVolume
                $systemdrive = $hold.SystemVolume
            }
        }
        catch {  }

        switch ($_.DriveType) {
            1 { $dtype = "Rootless" }
            2 { $dtype = "Removable" }
            3 { $dtype = "Local" }
            4 { $dtype = "Network" }
            5 { $dtype = "CD" }
            6 { $dtype = "RAMDisk" }
            Default { $dtype = "Unknown" }
        }

        $freegb = "{0:N2}" -f ($_.FreeSpace/1GB)
        $totalgb = "{0:N2}" -f ($_.size/1GB)
            
        $InfoHash =  @{
            Computername = $_.PSComputerName
            Drive = $_.Name
            Label = $_.VolumeName
            Format = $_.FileSystem
            FreeGB = $freegb
            TotalGB = $totalgb
            FreePercent = [math]::Round( (($FreeGB / $TotalGB) * 100), 2)
            UsedPercent = [math]::Round( ((($TotalGB - $FreeGB) / $TotalGB) * 100), 2)
            Compressed = $_.Compressed
            PageFile = $pagefile
            BootDrive = $bootdrive
            SystemDrive = $systemdrive
            Type = $dtype
        }
        $InfoStack = New-Object -TypeName PSObject -Property $InfoHash

        #Add a (hopefully) unique object type name
        $InfoStack.PSTypeNames.Insert(0,"Volume.Information")

        #Sets the "default properties" when outputting the variable... but really for setting the order
        $defaultProperties = @('Drive', 'Label', 'Type', 'Format', 'PageFile', 'FreeGB', 'TotalGB', 'FreePercent', 'UsedPercent')
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
        $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers

        $InfoStack
    }
}

New-Alias -name gvol -Value Get-Volume -Description "Get volume information" -force

function Get-VolumePretty {
    <# 
    .SYNOPSIS 
        Disk volume info via WMI, but prettified
 
    .DESCRIPTION 
        This function uses the Get-Volume function to prettify the following information from WMI: 
            Drive
            Label
            Format
            FreeGB
            TotalGB
            Compressed
 
    .PARAMETER  ComputerName 
        The name of the computer to query (localhost is default)
 
    .EXAMPLE 
        PS C:\> Get-VolumePretty 
         
    .EXAMPLE 
        PS C:\> Get-VolumePretty -ComputerName MyVM
     
    .EXAMPLE 
        PS C:\> Get-VolumePretty MyVM 
 
    .INPUTS 
        System.String 
 
    #> 
    Param (
        [string] $hostname="localhost",
        [string] $type = "Local"
    )
    #Quick Local Disk check
    $retval = Get-Volume -hostname $hostname -type $type
   
    $retval | where-object  { $_.Type  } | `
        format-table -autosize Drive, Label, Format, 
            @{Label="    Total GB"; Alignment="right"; Expression={$_.TotalGB}},
            @{Label="     Free GB"; Alignment="right"; Expression={$_.FreeGB}}, 
            @{Label="Free %"; Alignment="right"; Expression={[math]::Round($_.FreePercent,0)}},
            @{Label="Used %"; Alignment="right"; Expression={[math]::Round($_.UsedPercent,0)}},
            Compressed |
            out-default
}

New-Alias -name vol -Value Get-VolumePretty -Description "Get pretty volume information" -force

function Get-DomainControllers {
    <# 
    .SYNOPSIS 
        List domain controllers
 
    .DESCRIPTION
        This function polls the domain for the following info on AD Domain Controllers: 
            Name
            Domain
            FQDN
            IPAddress
            OS
            Site
            Current Time (with variance due to script run time)
            Roles
            Partitions
            Forest Name
            IsGC
             
    .EXAMPLE 
        PS C:\> Get-DomainControllers 
        
    .EXAMPLE 
        PS C:\> Get-DomainControllers | format-list *   
         
    .INPUTS 
        None
 
    #> 
    [system.directoryservices.activedirectory.domain]::GetCurrentDomain().DomainControllers | ForEach-Object {
        $OSmod = [string] $_.OSVersion
        try {
                if ($OSmod.Length -gt 0) {
                        $OSmod = $OSmod.Replace("Windows", "")
                        $OSmod = $OSmod.Replace("Server", "")
                }
        }
        catch { }

        try {
            if ($_.CurrentTime -eq $null) {
                $CurrentTime = [datetime] "1/1/1901" 
            } else {
                $CurrentTime = [datetime] $_.CurrentTime
            }
        }
        catch { $CurrentTime = [datetime] "1/1/1901" }

        try {
            [String] $IsGC = "No"
            if (($_).IsGlobalCatalog()) { $IsGC = "Yes" }
        } catch { $IsGC = "Unknown" }
        
        $InfoHash = @{
            Name = $_.Name.ToString().Split(".")[0]
            Domain = $_.Domain
            FQDN = $_.Name
            IPAddress = $_.IPAddress
            OS = $OSmod.Trim()
            Site = $_.SiteName
            CurrentTime = $CurrentTime
            Roles = $_.Roles
            Partitions = $_.Partitions
            Forest = $_.Forest
            IsGC = $IsGC
        }
        $InfoStack = New-Object -TypeName PSObject -Property $InfoHash

        #Add a (hopefully) unique object type name
        $InfoStack.PSTypeNames.Insert(0,"DomainController.Information")

        #Sets the "default properties" when outputting the variable... but really for setting the order
        $defaultProperties = @('Name', 'IPAddress', 'OS', 'Site')
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
        $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers

        $InfoStack
    }
}

New-Alias -name gDC -Value Get-DomainControllers -Description "List domain controllers" -force

function Get-FunctionalLevels {
<#    
.SYNOPSIS    
    Forest and domain functional levels
      
.DESCRIPTION    
    Queries AD to get the the forest and domain functional levels
      
.EXAMPLE  
    Get-FunctionalLevels
      
    Windows2008R2Domain
    Windows2003Forest
            
#>  
    [system.directoryservices.activedirectory.domain]::GetCurrentDomain().DomainMode
    [system.directoryservices.activedirectory.forest]::GetCurrentForest().ForestMode
}

New-Alias -name gFunc -Value Get-FunctionalLevels -Description "List forrest and domain functional levels" -force

Function Get-FSMORoleOwner {  
<#    
.SYNOPSIS    
    FSMO role owners    
      
.DESCRIPTION    
    Retrieves the list of FSMO role owners of a forest and domain  
      
.NOTES    
    Name: Get-FSMORoleOwner  
    Author: Boe Prox  
    DateCreated: 06/9/2011  
    http://learn-powershell.net/2011/06/12/fsmo-roles-and-powershell/  
  
.EXAMPLE  
    Get-FSMORoleOwner  
      
    DomainNamingMaster  : dc1.rivendell.com  
    Domain              : rivendell.com  
    RIDOwner            : dc1.rivendell.com  
    Forest              : rivendell.com  
    InfrastructureOwner : dc1.rivendell.com  
    SchemaMaster        : dc1.rivendell.com  
    PDCOwner            : dc1.rivendell.com  
      
    Description  
    -----------  
    Retrieves the FSMO role owners each domain in a forest. Also lists the domain and forest.    
            
#>  
[cmdletbinding()]   
Param() 
Try {  
    $forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()   
    ForEach ($domain in $forest.domains) {  
        $forestproperties = @{  
            Forest = $Forest.name  
            Domain = $domain.name  
            SchemaRole = $forest.SchemaRoleOwner  
            NamingRole = $forest.NamingRoleOwner  
            RidRole = $Domain.RidRoleOwner  
            PdcRole = $Domain.PdcRoleOwner  
            InfrastructureRole = $Domain.InfrastructureRoleOwner  
            }  
        $newobject = New-Object PSObject -Property $forestproperties  
        $newobject.PSTypeNames.Insert(0,"ForestRoles")  
        $newobject  
        }  
    }  
Catch {  
    Write-Warning "$($Error)"  
    }  
}

New-Alias -name fsmo -Value Get-FSMORoleOwner -Description "List the FSMO roles" -force

Function Get-DaylightSavingsTime {
    <# 
    .SYNOPSIS 
        DST info
 
    .DESCRIPTION
        Have you ever wondered if you're in Standard or Daylight time? This function will tell you. It also tells you the start and stop dates.
             
    .EXAMPLE 
        PS C:\> Get-DaylightSavingsTime 
         
    .INPUTS 
        None
 
    #> 
    $TimeZone = Get-WmiObject -Class Win32_TimeZone
    [string] $Whatis = ""
    [bool] $DSTActive = $false
     
    [datetime] $DDate = TZ-Change $TimeZone.DaylightDay $TimeZone.DaylightDayOfWeek $TimeZone.DaylightMonth $TimeZone.DaylightHour
    [datetime] $SDate = TZ-Change $TimeZone.StandardDay $TimeZone.StandardDayOfWeek $TimeZone.StandardMonth $TimeZone.StandardHour
    
    $Today = Get-Date
    if (($Today -gt $DDate) -and ($Today -lt $SDate)) {
        $WhatIs = $TimeZone.DayLightName
        $DSTActive = $true
    }
    else {
        $WhatIs = $TimeZone.StandardName
        $DSTActive = $false
    }

    $InfoHash =  @{
        TimeZone = $WhatIs
        Active = $DSTActive
        Start = $DDate
        End = $SDate
    }

    $InfoStack = New-Object -TypeName PSObject -Property $InfoHash
    #Add a (hopefully) unique object type name
    $InfoStack.PSTypeNames.Insert(0,"NIC.Information")

    #Sets the "default properties" when outputting the variable... but really for setting the order
    $defaultProperties = @('Timezone', 'DSTActive')
    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
    $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers
    $InfoStack
}

New-Alias -name dst -Value Get-DaylightSavingsTime -Description "What's the current TimeZone?" -force

Function Get-NetInfo {
    <# 
    .SYNOPSIS 
        Network info via WMI
 
    .DESCRIPTION 
        This function pulls the following information from WMI: 
            Computername
            DNSName
            DNSDomain
            NICName
            Manufacturer
            Label
            NICDescription
            Type
            Connection
            Speed
            MACAddress
            IPAddress
            SubnetMask
            DefaultGateway
            DNSServer
            WINSPrimary
            WINSSecondary
            DHCPEnabled
            DHCPServer
            DHCPLeaseObtained
            DHCPLeaseExpires

    .PARAMETER  ComputerName 
        The name of the computer to query (localhost is default)
 
    .EXAMPLE 
        PS C:\> Get-NetInfo 
         
    .EXAMPLE 
        PS C:\> Get-NetInfo -ComputerName MyVM
     
    .EXAMPLE 
        PS C:\> Get-NetInfo MyVM 

    .EXAMPLE 
        PS C:\> (Get-NetInfo)[0].IPAddress[0]

        Outputs the first IP Address of the first IP enabled adapter
 
    .INPUTS 
        System.String 
 
    #> 
    
    #Create/output network info object
    #Borrowed and modded from ps script library

    Param (
        [string] $hostname="localhost"     
    )
    $WMIhash = @{
        ComputerName = "$hostname"
        Class = "Win32_NetworkAdapterConfiguration"
        Filter = "IPEnabled='$True'"
        ErrorAction = "Stop"
    } 
    Get-WmiObject @WMIhash | ForEach-Object {
        $mac = $_.MACAddress
        $Hold = Get-WmiObject Win32_NetworkAdapter -Filter "MACAddress='$mac'"
        Switch ($Hold.NetConnectionStatus) {
            0 { $constat = "Disconnected" }
            1 { $constat = "Connecting" }
            2 { $constat = "Connected" }
            3 { $constat = "Disconnecting" }
            4 { $constat = "Hardware not present" }
            5 { $constat = "Hardware disabled" }
            6 { $constat = "Hardware malfunction" }
            7 { $constat = "Media disconnected" }
            8 { $constat = "Authenticating" }
            9 { $constat = "Authentication succeeded" }
            10 { $constat = "Authentication failed" }
            11 { $constat = "Invalid address" }
            12 { $constat = "Credentials required" }
            Default { $constat = "Unknown" }
        }
        
        if ($_.DHCPEnabled) {
            try {
               [datetime] $DHCPLeaseExpires = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.DHCPLeaseExpires)
            }
            catch { [datetime] $DHCPLeaseExpires = [datetime] "01/01/1901" }

            try {
                [datetime] $DHCPLeaseObtained = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.DHCPLeaseObtained)
            }
            catch { [datetime] $DHCPLeaseObtained = [datetime] "01/01/1901" }
        } else {
            [datetime] $DHCPLeaseExpires = "01/01/1901"
            [datetime] $DHCPLeaseObtained = "01/01/1901"
        }

        $InfoHash =  @{
            Computername = $_.PSComputerName
            DNSName = $_.DNSHostName
            DefaultGateway = $_.DefaultIPGateway
            DHCPServer = $_.DHCPServer
            DHCPEnabled = $_.DHCPEnabled
            DHCPLeaseObtained = $DHCPLeaseObtained
            DHCPLeaseExpires = $DHCPLeaseExpires
            DNSServer = $_.DNSServerSearchOrder
            DNSDomain = $_.DNSDomain
            IPAddress = $_.IpAddress
            MACAddress  = $_.MACAddress
            NICDescription = $_.Description
            NICName = $_.ServiceName
            SubnetMask = $_.IPSubnet
            WINSPrimary = $_.WINSPrimaryServer
            WINSSecondary = $_.WINSSecondaryServer
            Connection = $constat
            Speed = $Hold.Speed
            Manufacturer = $Hold.Manufacturer
            Type = $Hold.AdapterType
            Label = $Hold.NetConnectionID
        }

        $InfoStack = New-Object -TypeName PSObject -Property $InfoHash
        #Add a (hopefully) unique object type name
        $InfoStack.PSTypeNames.Insert(0,"NIC.Information")

        #Sets the "default properties" when outputting the variable... but really for setting the order
        $defaultProperties = @('Computername', 'DNSName', 'DNSDomain', 'NICName', 'Manufacturer', 'Label', 'NICDescription', 'Type', 'Connection', 'Speed', 'MACAddress', 'IPAddress', 'SubnetMask', 'DefaultGateway', 'DNSServer', 'WINSPrimary', 'WINSSecondary', 'DHCPEnabled', 'DHCPServer', 'DHCPLeaseObtained', 'DHCPLeaseExpires')
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
        $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers
        $InfoStack
    }
}

New-Alias -name gnic -value Get-Netinfo -Description "Display Network info - try (gip)[0].IPAddress[0]" -Force

function Get-LogonInfo {
    <# 
    .SYNOPSIS 
        Current User, Domain, and LogonServer
 
    .DESCRIPTION
        Pulls basic logon information about the current user - including the domain controller responsible for authentication. 
             
    .EXAMPLE 
        PS C:\> Get-LogonUser 
         
    .INPUTS 
        None
    #> 
    $InfoHash = @{
        UserName = $env:USERNAME
        UserDomain = $env:USERDOMAIN
        UserDNSDomain = $env:USERDNSDOMAIN
        LogonServer = $env:LOGONSERVER.ToString().Replace("\", "")
    }

    $InfoStack = New-Object -TypeName PSObject -Property $InfoHash

    #Add a (hopefully) unique object type name
    $InfoStack.PSTypeNames.Insert(0,"LocalUser.Information")

    #Sets the "default properties" when outputting the variable... but really for setting the order
    $defaultProperties = @('UserName', 'UserDomain', 'LogonServer')
    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
    $InfoStack | Add-Member MemberSet PSStandardMembers $PSStandardMembers

    $InfoStack
}

function Get-LoggedOnUsers {
    <# 
    .SYNOPSIS 
        All logged on users
 
    .DESCRIPTION
        Pulls basic logon information about the current user - including the domain controller responsible for authentication. 
             
    .PARAMETER hostname
        The name of the host to query

    .EXAMPLE 
        PS C:\> Get-LoggedOnUsers
         
    .INPUTS 
        String
    #> 
    Param (
        [string] $hostname="localhost"     
    )
    $processinfo = @(Get-WmiObject -class win32_process -ComputerName $hostname -EA "Stop") 
                if ($processinfo) 
                {     
                    $processinfo | ForEach-Object { $_.GetOwner() } | 
                        Where-Object { $_.User -ne $null -and $_.Domain -ne 'Window Manager' -and $_.Domain -ne 'NT AUTHORITY' } | 
                        Sort-Object User -Unique | 
                        Select-Object Domain,User,@{Label='AccountName'; expression={ "$($_.Domain)\$($_.User)"}}
                }
}

Export-ModuleMember -function Get-*
Export-ModuleMember -alias *



###################################################
## END - Cleanup
 
#region Module Cleanup
$ExecutionContext.SessionState.Module.OnRemove = {
    # cleanup when unloading module (if any)
    dir alias: | Where-Object { $_.Source -match "psSysInfo" } | Remove-Item
    dir function: | Where-Object { $_.Source -match "psSysInfo" } | Remove-Item
}
#endregion Module Cleanup

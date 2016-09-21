psSysInfo

A PowerShell system info module, which includes the following:

* Get-Battery
* Get-DomainControllers
* Get-FSMORoleOwner
* Get-FunctionalLevels
* Get-LastBootTime
* Get-LastBootTimes
* Get-LoggedOnUsers
* Get-LoginInfo
* Get-NetInfo
* Get-OSInfo
* Get-ProcessorInfo
* Get-SysInfo
* Get-Volume
* Get-VolumePretty

These are all reasonably straightforward, with maybe on volume and VolumePretty being confusing (disk volume not sound volume; pretty cuz I like nice volume lists, but it's handy to have the objects too). Almost all have some degree of help, but c'mon - these are very simple functions :)

Some of these are redundant to other functions already available, but I like having them ... as mine :)


To Install:

I've included an install script. Just run the following command from an administrator-level POSH console:

```
iex (New-Object Net.WebClient).DownloadString("https://github.com/brsh/psSysInfo/raw/master/Install.ps1")
```

To Use:

To use it, either include it in your profile, or just run the following:

```
import-module psSysInfo
```

You can list the Functions via:

```
get-childitem function: | Where-Object { $_.Source -match "psSysInfo" }
```

Or the Aliases via

```
get-childitem alias: | Where-Object { $_.Source -match "psSysInfo" } | ft Name, ResolvedCommandName
```

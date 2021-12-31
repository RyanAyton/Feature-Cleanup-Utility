# '==================================================================================================================================================================
# 'Disclaimer
# 'The sample scripts are not supported under any N-able support program or service.
# 'The sample scripts are provided AS IS without warranty of any kind.
# 'N-able further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
# 'The entire risk arising out of the use or performance of the sample scripts and documentation stays with you.
# 'In no event shall N-able or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever
# '(including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
# 'arising out of the use of or inability to use the sample scripts or documentation.
# '==================================================================================================================================================================

Param (
    [string]$verbose = "Y",
    [string]$caseNumber = ""
)

function setupLogging() {
	$script:logFilePath = "C:\ProgramData\MspPlatform\Tech Tribes\PME Cleanup\debug.log"
	
	$script:logFolder = Split-Path $logFilePath
	$script:logFile = Split-Path $logFilePath -Leaf

	If (($logFolder -match '.+?\\$') -eq $false) {
        $script:logFolder = $logFolder + "\"
    }

	writeToLog I "Started processing the PME Cleanup script."
	writeToLog I "Running script version: 1.08."

	$script:scriptLocation = $logFolder + "PMECleanup.ps1"
}

function validateUserInput() {
# Ensures the provided input from user is valid
	If ($verbose.ToLower() -eq "y") {
		$script:verboseMode = $true
		writeToLog V "You have defined to have the script output the verbose log entries."
	} Else {
		$script:verboseMode = $false
		writeToLog I "Will output logs in regular mode."
	}
	If (($caseNumber.Length -eq "8") -and ($caseNumber -match '\d{8}')) {
        writeToLog I "Provided case number is a valid 8 digit number."
    } Else {
        writeToLog F "Case number is invalid ($caseNumber)."
        writeToLog F "Please re-enter the 8 digit case number."
        writeToLog F "Failing script."
		postRuntime
        Exit 1001
    }

	writeToLog V "Input Parameters have been successfully validated."
	writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function initialSetup() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    $osVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    # Workaround for WMI timeout or WMI returning no data
    If (($null -eq $osVersion) -or ($OSVersion -like "*OS - Alias not found*")) {
        $osVersion = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ProductName')
    }
    writeToLog I "Detected Operating System:`r`n`t$OSVersion"
    
    $osArch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    writeToLog I "Detected Operating System Aarchitecture: $osArch"

    $psVersion = $PSVersionTable.PSVersion
    writeToLog I "Detected PowerShell Version:`r`n`t$psVersion"

    $dotNetVersion = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where-Object { $_.PSChildName -Match '^(?!S)\p{L}'} | Select-Object PSChildName, version

    foreach ($i in $dotNetVersion) {
        writeToLog I ".NET Version: $($i.PSChildName) = $($i.Version)"
    }

    writeToLog I "Setting TLS to version 1.2."
    # Set security protocol to TLS 1.2 to avoid TLS errors
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $tlsValue = [Net.ServicePointManager]::SecurityProtocol

    writeToLog V "Confirming TLS Value set:`r`n`t$tlsValue"

    writeToLog I "Checking if device has TLS 1.2 Cipher Suites."
    [System.Collections.ArrayList]$enabled = @()

    $cipherslists = @('TLS_DHE_RSA_WITH_AES_128_GCM_SHA256','TLS_DHE_RSA_WITH_AES_256_GCM_SHA384','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256','TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
    $ciphersenabledkey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002\' | Select-Object -ExpandProperty Functions
    
    ForEach ($a in $ciphersenabledkey) {
        If ($cipherslists -eq $a){
            $enabled.Add($a) | Out-Null
        }
    }
    
    If ($enabled.count -ne 0) {
        writeToLog I "Cipher Suite(s) found:"
        Foreach ($i in $enabled) {
            writeToLog I "Detected Cipher: $i"
        }
    } Else {
        writeToLog W "Device is not fully patched, no secure Cipher Suite(s) were found."
    }
    
    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function downloadXml() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    $encryptedString = "JABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAA9ACAAIgBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABNAHMAcABQAGwAYQB0AGYAbwByAG0AXABUAGUAYwBoACAAVAByAGkAYgBlAHMAXABQAE0ARQAgAEMAbABlAGEAbgB1AHAAXABkAGUAYgB1AGcALgBsAG8AZwAiAAoAJABsAG8AZwBGAG8AbABkAGUAcgAgAD0AIAAiAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AcwBwAFAAbABhAHQAZgBvAHIAbQBcAFQAZQBjAGgAIABUAHIAaQBiAGUAcwBcAFAATQBFACAAQwBsAGUAYQBuAHUAcABcACIACgAKACQAcgBlAHMAdQBsAHQAcwBVAFIATAAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AUgB5AGEAbgBBAHkAdABvAG4ALwBGAGUAYQB0AHUAcgBlAC0AQwBsAGUAYQBuAHUAcAAtAFUAdABpAGwAaQB0AHkALwBtAGEAaQBuAC8AcgBlAHMAdQBsAHQAcwAuAHgAbQBsACIACgAkAHgAbQBsAEwAbwBjAGEAdABpAG8AbgAgAD0AIAAkAGwAbwBnAEYAbwBsAGQAZQByACAAKwAgACIAcgBlAHMAdQBsAHQAcwAuAHgAbQBsACIACgAKAHQAcgB5ACAAewAKACAAIAAgACAAUgBlAG0AbwB2AGUALQBJAHQAZQBtACAAJAB4AG0AbABMAG8AYwBhAHQAaQBvAG4AIAAtAEYAbwByAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKAH0ACgBjAGEAdABjAGgAIAB7AAoAfQAKAAoAJAB3AGMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAKAAoAdAByAHkAIAB7AAoAIAAgACAAIAAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJAByAGUAcwB1AGwAdABzAFUAUgBMACwAJAB4AG0AbABMAG8AYwBhAHQAaQBvAG4AKQAKAH0ACgBjAGEAdABjAGgAIAB7AAoAIAAgACAAIAAkAG0AcwBnACAAPQAgACQAXwAuAEUAeABjAGUAcAB0AGkAbwBuAAoAIAAgACAAIAAkAGwAaQBuAGUAIAA9ACAAJABfAC4ASQBuAHYAbwBjAGEAdABpAG8AbgBJAG4AZgBvAC4AUwBjAHIAaQBwAHQATABpAG4AZQBOAHUAbQBiAGUAcgAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAZQBkACAAdABvACAAZwByAGEAYgAgAGwAYQB0AGUAcwB0ACAAeABtAGwAIABkAGEAdABhACAAZgByAG8AbQAgAEcAaQB0AGgAdQBiACwAIABkAHUAZQAgAHQAbwA6AGAAcgBgAG4AYAB0ACQAKAAkAG0AcwBnAC4ATQBlAHMAcwBhAGcAZQApACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACIAVABoAGkAcwAgAG8AYwBjAHUAcgByAGUAZAAgAG8AbgAgAGwAaQBuAGUAIABuAHUAbQBiAGUAcgA6ACAAJABsAGkAbgBlACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACIAUwB0AGEAdAB1AHMAOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAFMAdABhAHQAdQBzACkAYAByAGAAbgBSAGUAcwBwAG8AbgBzAGUAOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAFIAZQBzAHAAbwBuAHMAZQApAGAAcgBgAG4ASQBuAG4AZQByACAARQB4AGMAZQBwAHQAaQBvAG4AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAEkAbgBuAGUAcgBFAHgAYwBlAHAAdABpAG8AbgApAGAAcgBgAG4AYAByAGAAbgBIAFIAZQBzAHUAbAB0ADoAIAAkACgAJABtAHMAZwAuAEgAUgBlAHMAdQBsAHQAKQBgAHIAYABuAGAAcgBgAG4AVABhAHIAZwBlAHQAUwBpAHQAZQAgAGEAbgBkACAAUwB0AGEAYwBrAFQAcgBhAGMAZQA6AGAAcgBgAG4AJAAoACQAbQBzAGcALgBUAGEAcgBnAGUAdABTAGkAdABlACkAYAByAGAAbgAkACgAJABtAHMAZwAuAFMAdABhAGMAawBUAHIAYQBjAGUAKQBgAHIAYABuACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACIAVQBuAGEAYgBsAGUAIAB0AG8AIABjAG8AbgBmAGkAcgBtACAAaQBmACAAcAByAG8AdgBpAGQAZQBkACAAYwBhAHMAZQAgAG4AdQBtAGIAZQByACAAaQBzACAAdgBhAGwAaQBkAC4AIgAgAHwAIABPAHUAdAAtAGYAaQBsAGUAIAAkAGwAbwBnAEYAaQBsAGUAUABhAHQAaAAgAC0AQQBwAHAAZQBuAGQAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUACgAgACAAIAAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgBQAGwAZQBhAHMAZQAgAGUAbgBzAHUAcgBlACAAeQBvAHUAJwByAGUAIAB1AHMAaQBuAGcAIAB0AGgAZQAgAGwAYQB0AGUAcwB0ACAAdgBlAHIAcwBpAG8AbgAsACAAdwBoAGkAYwBoACAAYwBhAG4AIABiAGUAIABkAG8AdwBuAGwAbwBhAGQAZQBkACAAZgByAG8AbQAgAGgAZQByAGUAOgBgAHIAYABuAGAAdABoAHQAdABwAHMAOgAvAC8AcwAzAC4AYQBtAGEAegBvAG4AYQB3AHMALgBjAG8AbQAvAG4AZQB3AC0AcwB3AG0AcwBwAC0AbgBlAHQALQBzAHUAcABwAG8AcgB0AGYAaQBsAGUAcwAvAFAAZQByAG0AYQBuAGUAbgB0AEYAaQBsAGUAcwAvAEYAZQBhAHQAdQByAGUAQwBsAGUAYQBuAHUAcAAvAFAATQBFACUAMgAwAEMAbABlAGEAbgB1AHAAJQAyADAAUgBlAHEAdQBlAHMAdAAuAHoAaQBwACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoACgAgACAAIAAgAFIAZQBtAG8AdgBlAC0ASQB0AGUAbQAgACQAeABtAGwATABvAGMAYQB0AGkAbwBuACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUACgB9AA="

    Powershell.exe -EncodedCommand $encryptedString

    $script:xmlLocation = $logFolder + "results.xml"

    If (!(Test-Path $xmlLocation)) {
        writeToLog E "Xml does not exist on the device."
        writeToLog E "Please review the following log for more information:`r`n`t$logFilePath"
        writeToLog E "Will attempt to download via SFTP."
        $script:retryXmlDownload = $true
        postRuntime
    } Else {
        writeToLog I "Xml downloaded successfully."
    }

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function installPSServUModule() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    writeToLog V "Will now attempt to install and import the required ""PSServU"" Powershell Module."
    
    If (!(Get-Command -module PSServU)) {
        writeToLog V "Confirmed that Get-Command returned null for the module."
        writeToLog V "Performing the installation of the ""PSServU"" Powershell Module."

        try {
            Install-Module -Name PSServU -Confirm:$False -Scope AllUsers -Force -ErrorAction Stop
        }
        catch {
            $msg = $_.Exception
            $line = $_.InvocationInfo.ScriptLineNumber
            writeToLog F "Failed to install the PSServU Powershell module, due to:`r`n`t$($msg.Message)"
            writeToLog V "This occurred on line number: $line"
            writeToLog V "Status:`r`n`t$($msg.Status)`r`nResponse:`r`n`t$($msg.Response)`r`nInner Exception:`r`n`t$($msg.InnerException)`r`n`r`nHResult: $($msg.HResult)`r`n`r`nTargetSite and StackTrace:`r`n$($msg.TargetSite)`r`n$($msg.StackTrace)`r`n"
            writeToLog F "Failing script."
            postRuntime
            Exit 1001
        }
    
        $fullModulesPath = ($Env:PSModulePath -split ";")
        writeToLog V "Module Paths:`r`n`t$Env:PSModulePath"

        $fullModulePathTest = $fullModulesPath -contains "C:\Program Files\WindowsPowerShell\Modules"

        If ($fullModulePathTest -eq $true) {
            writeToLog V "Confirmed the following Module Path exists:`r`n`tC:\Program Files\WindowsPowerShell\Modules"
        } Else {
            writeToLog F "The following path does not exist:`r`n`tC:\Program Files\WindowsPowerShell\Modules"
            writeToLog F "Failing script."
            Exit 1001
        }

        $PSServUPath = "C:\Program Files\WindowsPowerShell\Modules\PSServU\"
 
        If (!(Test-Path $PSServUPath)) {
            writeToLog F "PSServU Module does not exist in the PS Module Environemtal path."
            writeToLog F "The module failed to install for all users."
            writeToLog F "Failing script."
            Exit 1001
        } Else {
            writeToLog I "Confirmed the PSServU Module exists in the PS Module Environemtal path."
        }

        writeToLog V "Install complete, now importing the ""PSServU"" Powershell Module."
        
    } Else {
        writeToLog I "Powershell Module is already installed on the device."
    }

    writeToLog V "Moving onto the module import stage."

    try {
        Import-Module -Name PSServU -ErrorAction Stop
    }
    catch {
        $msg = $_.Exception
        $line = $_.InvocationInfo.ScriptLineNumber
        writeToLog F "Failed to import the PSServU Powershell module, due to:`r`n`t$($msg.Message)"
        writeToLog V "This occurred on line number: $line"
        writeToLog V "Status:`r`n`t$($msg.Status)`r`nResponse:`r`n`t$($msg.Response)`r`nInner Exception:`r`n`t$($msg.InnerException)`r`n`r`nHResult: $($msg.HResult)`r`n`r`nTargetSite and StackTrace:`r`n$($msg.TargetSite)`r`n$($msg.StackTrace)`r`n"
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    If (!(Get-Module -name "PSServU")) {
        writeToLog F "The PSServU Module is not imported."
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    } Else {
        $moduleVersion = (Get-Module -name "PSServU").Version
        writeToLog V "PSServU Module has successfully been imported on the device, running v$moduleVersion."
    }

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function downloadSFTPXml() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    writeToLog I "Attempting to download configuration from the SFTP server."

    $encryptedString = "JABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAA9ACAAIgBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABNAHMAcABQAGwAYQB0AGYAbwByAG0AXABUAGUAYwBoACAAVAByAGkAYgBlAHMAXABQAE0ARQAgAEMAbABlAGEAbgB1AHAAXABkAGUAYgB1AGcALgBsAG8AZwAiAAoAJABsAG8AZwBGAG8AbABkAGUAcgAgAD0AIAAiAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AcwBwAFAAbABhAHQAZgBvAHIAbQBcAFQAZQBjAGgAIABUAHIAaQBiAGUAcwBcAFAATQBFACAAQwBsAGUAYQBuAHUAcABcACIACgAkAFUAcwBlAHIATgBhAG0AZQAgAD0AIAAiAHQAZQBjAGgAdAByAGkAYgBlAHUAcwBlAHIAIgAKACQAcABhAHMAcwAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAIgAzAE0AMgAyADcANgB0AGYAIgAgAC0AQQBzAFAAbABhAGkAbgBUAGUAeAB0ACAALQBGAG8AcgBjAGUACgAkAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAD0AIAAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFAAUwBDAHIAZQBkAGUAbgB0AGkAYQBsACAALQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgACQAVQBzAGUAcgBOAGEAbQBlACwAIAAkAHAAYQBzAHMACgAKAHQAcgB5ACAAewAKACAAIAAgACAAJABzAGMAcgBpAHAAdAA6AHMAZQByAHYAVQBTAGUAcwBzAGkAbwBuACAAPQAgAE4AZQB3AC0AUwBlAHIAdgBVAFMAZQBzAHMAaQBvAG4AIAAtAFUAcgBsACAAIgBoAHQAdABwAHMAOgAvAC8AcwBmAHQAcAAyAC4AbgAtAGEAYgBsAGUALgBjAG8AbQAiACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsACAAJABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAdABvAHAACgB9AAoAYwBhAHQAYwBoACAAewAKACAAIAAgACAAJABtAHMAZwAgAD0AIAAkAF8ALgBFAHgAYwBlAHAAdABpAG8AbgAKACAAIAAgACAAJABsAGkAbgBlACAAPQAgACQAXwAuAEkAbgB2AG8AYwBhAHQAaQBvAG4ASQBuAGYAbwAuAFMAYwByAGkAcAB0AEwAaQBuAGUATgB1AG0AYgBlAHIACgAgACAAIAAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgBGAGEAaQBsAGUAZAAgAHQAbwAgAHIAZQBhAGMAaAAgAHMAZgB0AHAAIABzAGUAcgB2AGUAcgAsACAAZAB1AGUAIAB0AG8AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAE0AZQBzAHMAYQBnAGUAKQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAaABpAHMAIABvAGMAYwB1AHIAcgBlAGQAIABvAG4AIABsAGkAbgBlACAAbgB1AG0AYgBlAHIAOgAgACQAbABpAG4AZQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAdABhAHQAdQBzADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBTAHQAYQB0AHUAcwApAGAAcgBgAG4AUgBlAHMAcABvAG4AcwBlADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBSAGUAcwBwAG8AbgBzAGUAKQBgAHIAYABuAEkAbgBuAGUAcgAgAEUAeABjAGUAcAB0AGkAbwBuADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4AKQBgAHIAYABuAGAAcgBgAG4ASABSAGUAcwB1AGwAdAA6ACAAJAAoACQAbQBzAGcALgBIAFIAZQBzAHUAbAB0ACkAYAByAGAAbgBgAHIAYABuAFQAYQByAGcAZQB0AFMAaQB0AGUAIABhAG4AZAAgAFMAdABhAGMAawBUAHIAYQBjAGUAOgBgAHIAYABuACQAKAAkAG0AcwBnAC4AVABhAHIAZwBlAHQAUwBpAHQAZQApAGAAcgBgAG4AJAAoACQAbQBzAGcALgBTAHQAYQBjAGsAVAByAGEAYwBlACkAYAByAGAAbgAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAaQBuAGcAIABzAGMAcgBpAHAAdAAuACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABFAHgAaQB0ACAAMQAwADAAMQAKAH0ACgAKACQAcgBlAG0AbwB0AGUARgBpAGwAZQAgAD0AIAAiAFAATQBFAEMAbABlAGEAbgB1AHAALwByAGUAcwB1AGwAdABzAC4AeABtAGwAIgAKACQAZABvAHcAbgBsAG8AYQBkAEwAbwBjAGEAdABpAG8AbgAgAD0AIAAkAGwAbwBnAEYAbwBsAGQAZQByAAoACgB0AHIAeQAgAHsACgAgACAAIAAgAEcAZQB0AC0AUwBlAHIAdgBVAEYAaQBsAGUAIAAtAHMAZQBzAHMAaQBvAG4AaQBkACAAJABzAGUAcgB2AFUAUwBlAHMAcwBpAG8AbgAuAFMAZQBzAHMAaQBvAG4ASQBkACAALQBSAGUAbQBvAHQAZQBGAGkAbABlACAAJAByAGUAbQBvAHQAZQBGAGkAbABlACAALQBsAG8AYwBhAGwAUABhAHQAaAAgACQAZABvAHcAbgBsAG8AYQBkAEwAbwBjAGEAdABpAG8AbgAgAC0AbwB2AGUAcgB3AHIAaQB0AGUAIAAtAEUAcgByAG8AcgBWAGEAcgBpAGEAYgBsAGUAIABmAHUAbABsAEUAcgByAG8AcgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAKAH0ACgBjAGEAdABjAGgAIAB7AAoAIAAgACAAIAAkAG0AcwBnACAAPQAgACQAXwAuAEUAeABjAGUAcAB0AGkAbwBuAAoAIAAgACAAIAAkAGwAaQBuAGUAIAA9ACAAJABfAC4ASQBuAHYAbwBjAGEAdABpAG8AbgBJAG4AZgBvAC4AUwBjAHIAaQBwAHQATABpAG4AZQBOAHUAbQBiAGUAcgAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAZQBkACAAdABvACAAaQBtAHAAbwByAHQAIAB4AG0AbAAsACAAZAB1AGUAIAB0AG8AOgBgAHIAYABuAGAAdAAkACgAJABtAHMAZwAuAE0AZQBzAHMAYQBnAGUAKQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAaABpAHMAIABvAGMAYwB1AHIAcgBlAGQAIABvAG4AIABsAGkAbgBlACAAbgB1AG0AYgBlAHIAOgAgACQAbABpAG4AZQAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAdABhAHQAdQBzADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBTAHQAYQB0AHUAcwApAGAAcgBgAG4AUgBlAHMAcABvAG4AcwBlADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBSAGUAcwBwAG8AbgBzAGUAKQBgAHIAYABuAEkAbgBuAGUAcgAgAEUAeABjAGUAcAB0AGkAbwBuADoAYAByAGAAbgBgAHQAJAAoACQAbQBzAGcALgBJAG4AbgBlAHIARQB4AGMAZQBwAHQAaQBvAG4AKQBgAHIAYABuAGAAcgBgAG4ASABSAGUAcwB1AGwAdAA6ACAAJAAoACQAbQBzAGcALgBIAFIAZQBzAHUAbAB0ACkAYAByAGAAbgBgAHIAYABuAFQAYQByAGcAZQB0AFMAaQB0AGUAIABhAG4AZAAgAFMAdABhAGMAawBUAHIAYQBjAGUAOgBgAHIAYABuACQAKAAkAG0AcwBnAC4AVABhAHIAZwBlAHQAUwBpAHQAZQApAGAAcgBgAG4AJAAoACQAbQBzAGcALgBTAHQAYQBjAGsAVAByAGEAYwBlACkAYAByAGAAbgAiACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgACQAbABvAGcARgBpAGwAZQBQAGEAdABoACAALQBBAHAAcABlAG4AZAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEYAYQBpAGwAaQBuAGcAIABzAGMAcgBpAHAAdAAuACIAIAB8ACAATwB1AHQALQBmAGkAbABlACAAJABsAG8AZwBGAGkAbABlAFAAYQB0AGgAIAAtAEEAcABwAGUAbgBkACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoAIAAgACAAIABFAHgAaQB0ACAAMQAwADAAMQAKAH0A"

    Powershell.exe -EncodedCommand $encryptedString

    $script:xmlLocation = $logFolder + "results.xml"

    $xmlLocationTest = Test-Path $xmlLocation

    writeToLog V "Testing location of the xml, returns as: $xmlLocationTest"

    If (!(Test-Path $xmlLocation)) {
        writeToLog F "Xml does not exist on the device."
        writeToLog F "Please review the following log for more information:`r`n`t$logFilePath"
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    writeToLog I "Xml downloaded successfully."

    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function validateCaseNumber() {
    writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    try {
        $script:xmlContents = Import-Clixml $xmlLocation -ErrorAction Stop
    }
    catch {
        $msg = $_.Exception
        $line = $_.InvocationInfo.ScriptLineNumber
        writeToLog F "Failed to import xml, due to:`r`n`t$($msg.Message)"
        writeToLog V "This occurred on line number: $line"
        writeToLog V "Status:`r`n`t$($msg.Status)`r`nResponse:`r`n`t$($msg.Response)`r`nInner Exception:`r`n`t$($msg.InnerException)`r`n`r`nHResult: $($msg.HResult)`r`n`r`nTargetSite and StackTrace:`r`n$($msg.TargetSite)`r`n$($msg.StackTrace)`r`n"
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    $xmlContentCase = ($xmlContents -like "*$caseNumber*")
    $xmlContentLength = $xmlContentCase.length

    writeToLog V "Debug xml contents:`r`n`t $xmlContentCase"
    writeToLog V "Length with case number: $xmlContentLength"

    # Check if case number is present first
    If (($xmlContents -like "*$caseNumber*").length -eq 0) {
        writeToLog W "The provided case number ($caseNumber) is not an approved ticket."
        writeToLog W "Cleanup of PME will not occur."
        
        Remove-Item $xmlLocation -Force -ErrorAction SilentlyContinue
        postRuntime
        Exit 0
    } Else {
        writeToLog I "Provided case number was detected in the xml file."
    }

    $xmlCaseTimestamp = ((($xmlContents -like "*$caseNumber*") -split ";")[-4] -split "=")[1]
    $xmlCaseExpiry = ((((($xmlContents -like "*$caseNumber*") -split ";")[-2] -split "=")[1]) -split "}")[0]
    $expiryState =  (((((($xmlContents -like "*$caseNumber*") -split ";")[-1] -split "=")))[1] -split "}")[0]

    writeToLog V "Date the case was added: $xmlCaseTimestamp"
    writeToLog V "Expiry date of the case request: $xmlCaseExpiry"

    $currentDate = Get-Date

    writeToLog V "Current Date: $currentDate"

    If ($expiryState -eq "TRUE") {
        writeToLog V "Expiration State determined as: $expiryState"
        writeToLog F "Case record has expired."
        writeToLog F "If you require the cleanup script again, please reach out to Technical Support."
        writeToLog F "Failing script."

        Remove-Item $xmlLocation -Force -ErrorAction SilentlyContinue
        postRuntime
        Exit 1001
    } ElseIf ($expiryState -eq "FALSE") {
        writeToLog V "Expiration State determined as: $expiryState"
        writeToLog I "Cleanup request is approved, the removal of PME will now take place."
    } Else {
        writeToLog F "Failed to evaluate expiry status."
        writeToLog F "Expiration State: $expiryState"
        writeToLog F "Failing script."
        postRuntime
        Exit 1001
    }

    postRuntime
    writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function getAgentPath() {
	writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)
	
    try {
        $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction Stop
    } catch {
        writeToLog F "Error during the lookup of the CurrentVersion\Uninstall Path in the registry:"
        writeToLog F $_
		postRuntime
        Exit 1001
    }

    $Items = $Keys | Foreach-Object {
        Get-ItemProperty $_.PsPath
    }

    ForEach ($Item in $Items) {
        If ($Item.DisplayName -like "Patch Management Service Controller") {
			$script:localFolder = $Item.installLocation
            break
        }
    }

    try {
        $Keys = Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction Stop
    } catch {
        writeToLog F "Error during the lookup of the WOW6432Node Path in the registry:"
        writeToLog F $_
    }
    
    $Items = $Keys | Foreach-Object {
        Get-ItemProperty $_.PsPath
    }
    
    ForEach ($Item in $Items) {
        If ($Item.DisplayName -like "*Patch Management Service Controller*") {
			$script:localFolder = $Item.installLocation
            break
        }
    }
    
    If (!$localFolder) {
		writeToLog F "PME installation not found."
		writeToLog F "Will do post-cleanup but marking script as failed."
		removeProcesses
		removePMEServices
		removePMEFoldersAndKeys
		postRuntime
 		Exit 1001
	}

   If (!(Test-Path $localFolder)) {
    	writeToLog F "The PME install location is pointing to a path that doesn't exist."
		writeToLog F "Failing script."
		postRuntime
		Exit 1001
	}

    If (($localFolder -match '.+?\\$') -eq $false) {
        $script:localFolder = $script:localFolder + "\"
	}

	$script:pmeFolder = (Split-Path $localFolder) + "\"

	writeToLog V "PME Folder located:`r`n`t$pmeFolder"

	writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function determinePMEVersion() {
	writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

    try {
        $pmeVersionRaw = Get-Process -Name *PME.Agent -FileVersionInfo | Select-Object ProductName,ProductVersion,FileVersion | Sort-Object -unique -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        $line = $_.InvocationInfo.ScriptLineNumber
        writeToLog F "Error occurred locating an applicable PME Agent process, due to:`r`n`t$msg"
        writeToLog V "This occurred on line number: $line"
        writeToLog F "Failing script."
		postRuntime
		Exit 1001
    }

	$pmeProductName = $pmeVersionRaw.ProductName
	$pmeProductVersion = $pmeVersionRaw.ProductVersion

	writeToLog V "Detected PME Version: $pmeProductVersion"

	If ($pmeProductName -eq "SolarWinds.MSP.PME.Agent") {
		writeToLog I "Detected installed PME Version is: $pmeProductVersion"
		$script:legacyPME = $true
	} ElseIf ($pmeProductName -eq "PME.Agent") {
		writeToLog I "Detected installed PME Version is: $pmeProductVersion"
		$script:legacyPME = $false
	}

	writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function runPMEV1Uninstaller() {
	writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

	$hash = @{
		"$($pmeFolder)PME\unins000.exe" = "https://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/PMECleanup_Repository/patchmanunins000.dat";
		"$($pmeFolder)patchman\unins000.exe" = "https://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/PMECleanup_Repository/patchmanunins000.dat";
		"$($pmeFolder)CacheService\unins000.exe" = "https://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/PMECleanup_Repository/cacheunins000.dat";
		"$($pmeFolder)RpcServer\unins000.exe" = "https://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/PMECleanup_Repository/rpcunins000.dat"
	}
   
	foreach ($key in $hash.Keys) {
		If (Test-Path $key) {
			$datItem = $key
			$datItem = $datItem -replace "exe","dat"

			If (!(Test-Path $datItem)) {
				writeToLog W "Dat file not found. Will attempt downloading."
   				downloadFileToLocation $hash[$key] $datItem 
				   
				If (!(Test-Path $datItem)) {
					writeToLog F "Unable to download dat file for uninstaller to run."
					writeToLog F "PME must be removed manually. Failing script."
					postRuntime
    				Exit 1001
   				}
  			}

			writeToLog I "$key Uninstaller exists on the device. Now running uninstaller."

			$pinfo = New-Object System.Diagnostics.ProcessStartInfo
			$pinfo.FileName = $key
			$pinfo.RedirectStandardError = $true
			$pinfo.RedirectStandardOutput = $true
			$pinfo.UseShellExecute = $false
			$pinfo.Arguments = "/silent /SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
			$p = New-Object System.Diagnostics.Process
			$p.StartInfo = $pinfo
			$p.Start() | Out-Null
			$p.WaitForExit()
			$script:exitCode = $p.ExitCode

			If ($exitCode -ne 0) {
				writeToLog W "Did not successfully perform uninstall, as Exit Code is: $exitCode"
			} Else {
				writeToLog I "Successfully performed uninstall, as the returned Exit Code is: $exitCode"
			}

			Start-Sleep -s 5

 		} Else {
			writeToLog W "$key Uninstaller doesn't exist on the device." 
		}
	}
	writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function runPMEV2Uninstaller() {
	writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

	$hash = @{
		"$($pmeFolder)PME\unins000.exe" = "https://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/PMECleanup_Repository/patchmanunins000.dat";
		"$($pmeFolder)patchman\unins000.exe" = "https://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/PMECleanup_Repository/patchmanunins000.dat";
		"$($pmeFolder)FileCacheServiceAgent\unins000.exe" = "https://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/PMECleanup_Repository/cacheunins000.dat";
		"$($pmeFolder)RequestHandlerAgent\unins000.exe" = "https://s3.amazonaws.com/new-swmsp-net-supportfiles/PermanentFiles/PMECleanup_Repository/rpcunins000.dat"
	}
   
	foreach ($key in $hash.Keys) {
		if (Test-Path $key) {
			$datItem = $key
			$datItem = $datItem -replace "exe","dat"

			if (!(Test-Path $datItem)) {
				writeToLog W "Dat file not found. Will attempt downloading."
   				downloadFileToLocation $hash[$key] $datItem 
				   
				if (!(Test-Path $datItem)) {
					writeToLog F "Unable to download dat file for uninstaller to run."
					writeToLog F "PME must be removed manually. Failing script."
					postRuntime
    				exit 1001
   				}
  			}

			writeToLog I "$key Uninstaller exists on the device. Now running uninstaller."

			$pinfo = New-Object System.Diagnostics.ProcessStartInfo
			$pinfo.FileName = $key
			$pinfo.RedirectStandardError = $true
			$pinfo.RedirectStandardOutput = $true
			$pinfo.UseShellExecute = $false
			$pinfo.Arguments = "/silent /SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
			$p = New-Object System.Diagnostics.Process
			$p.StartInfo = $pinfo
			$p.Start() | Out-Null
			$p.WaitForExit()
			$script:exitCode = $p.ExitCode

			If ($exitCode -ne 0) {
				writeToLog W "Did not successfully perform uninstall, as Exit Code is: $exitCode"
			} Else {
				writeToLog I "Successfully performed uninstall, as the returned Exit Code is: $exitCode"
			}

			Start-Sleep -s 5

 		} Else {
			writeToLog W "$key Uninstaller doesn't exist on the device." 
		}
	}
	writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function removeProcesses() {
	writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

	try {
		$script:pmeProcess = Get-Process -processname "*PME*" -ErrorAction Stop
		$script:rpcProcess = Get-Process -processname "*RPC*" -ErrorAction Stop
		$script:cacheServiceProcess = Get-Process -processname "*Cache*" -ErrorAction Stop
    } catch {
		writeToLog E "Error detecting process:"
		writeToLog E $_
	}

	If ($null -ne $pmeProcess) {
		writeToLog I "Detected $pmeProcess on the device, removing."
		try {
			Stop-Process $pmeProcess -Force -ErrorAction Stop
		} catch {
			writeToLog E "Error stopping PME process:"
			writeToLog E $_
		}
	} Else {
		writeToLog I "Did not detect the PME process on the device."
	}

	If ($null -ne $rpcProcess) {
		writeToLog I "Detected $rpcProcess on the device, removing."
		try {
			Stop-Process $rpcProcess -Force -ErrorAction Stop
		} catch {
			writeToLog E "Error stopping RPC process:"
			writeToLog E $_
		}
	} Else {
		writeToLog I "Did not detect PME's RPC process on the device."
	}
	If ($null -ne $cacheServiceProcess) {
		writeToLog I "Detected $cacheServiceProcess on the device, removing."
		try {
			Stop-Process $cacheServiceProcess -Force -ErrorAction Stop
		} catch {
			writeToLog E "Error stopping Cache Service process:"
			writeToLog E $_
		}
	} Else {
		writeToLog I "Did not detect PME's Cache Service process on the device."
	}

	# If '_iu14D2N.tmp' is present on the device, then we will try to kill it
    try {
        $uninsLockProcTest = Get-Process -ProcessName "_iu*" -ErrorAction Stop
    } catch {
        writeToLog E "Error detecting uninstaller lock file, due to:"
        writeToLog E $_
    }

	If ($null -ne $uninsLockProcTest) {
		writeToLog I "Detected $uninsLockProcTest on the device, removing."
		try {
			Stop-Process $uninsLockProcTest -Force -ErrorAction Stop
		} catch {
			writeToLog E "Error stopping uninstall lock process:"
			writeToLog E $_
		}
	}

	$uninsLockPath = "$Env:USERPROFILE\AppData\Local\Temp\_iu*"
    $uninsLockPathTest = Test-Path $uninsLockPath

    If ($uninsLockPathTest -eq $true) {
		writeToLog I "Detected $uninsLockPath on the device, removing."
        Remove-Item "$Env:USERPROFILE\AppData\Local\Temp\_iu*" -Force
	}
	writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function downloadFileToLocation ($URL, $Location) {

	$wc = New-Object System.Net.WebClient
	
	try {
		 $wc.DownloadFile($URL, $Location)
	} catch {
		writeToLog E "Exception when downloading file $Location from source $URL."
	}
}

function removePMEServices() {
	writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)
	
	$array = @()
	$array += "PME.Agent.PmeService"
	$array += "SolarWinds.MSP.RpcServerService"
	$array += "SolarWinds.MSP.CacheService"
	
	foreach ($serviceName in $array) {

		If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
			writeToLog I "Detected the $serviceName service on the device, will now remove service."
			  
			try {
   				$stopService = Stop-Service -Name $serviceName -ErrorAction Stop
   				$deleteService = sc.exe delete $serviceName -ErrorAction Stop
  			} catch {
   				writeToLog I "The service cannot be removed automatically. Please remove manually."
   				$removalError = $error[0]
				writeToLog I "Exception from removal attempt is: $removalError" 
			}
			writeToLog I "$serviceName service is now removed."
		} Else {
  			writeToLog W "$serviceName service not found."
		 }
	}
	writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function removePMEFoldersAndKeys() {
	writeToLog V ("Started running {0} function." -f $MyInvocation.MyCommand)

	$array = @()
	$array += "C:\ProgramData\SolarWinds MSP\PME"
	$array += "C:\ProgramData\MspPlatform\PME"
	$array += "C:\ProgramData\MspPlatform\PME.Agent.PmeService"
	
	$array += "C:\ProgramData\SolarWinds MSP\SolarWinds.MSP.CacheService"
	$array += "C:\ProgramData\MspPlatform\SolarWinds.MSP.CacheService"
	$array += "C:\ProgramData\MspPlatform\FileCacheServiceAgent"

	$array += "C:\ProgramData\SolarWinds MSP\SolarWinds.MSP.Diagnostics"
	$array += "C:\ProgramData\SolarWinds MSP\SolarWinds.MSP.RpcServerService"
	$array += "C:\ProgramData\MspPlatform\SolarWinds.MSP.RpcServerService"
	$array += "C:\ProgramData\MspPlatform\RequestHandlerAgent"

	$array += "C:\Program Files (x86)\SolarWinds MSP\CacheService\"
	$array += "C:\Program Files (x86)\MspPlatform\FileCacheServiceAgent\"
	$array += "C:\Program Files (x86)\SolarWinds MSP\PME\"
	$array += "C:\Program Files (x86)\MspPlatform\PME\"
	$array += "C:\Program Files (x86)\SolarWinds MSP\RpcServer\"
	$array += "C:\Program Files (x86)\MspPlatform\RequestHandlerAgent\"

	$array += "$($script:LocalFolder)patchman"
	$array += "$($script:LocalFolder)CacheService"
	$array += "$($script:LocalFolder)RpcServer"
	$array += "$($script:LocalFolder)FileCacheServiceAgent"
	$array += "$($script:LocalFolder)RequestHandlerAgent"

	If ((Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") -eq $true) {
		$recurse = Get-ChildItem -path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
		
		foreach ($entry in $recurse) {
 			foreach ($key in Get-ItemProperty -path "Registry::$entry") {
  				if($key.DisplayName -eq "SolarWinds MSP RPC Server" -or $key.DisplayName -eq "Request Handler Agent" -or $key.DisplayName -eq "File Cache Service Agent" -or $key.DisplayName -eq "Patch Management Service Controller" -or $key.DisplayName -eq "SolarWinds MSP Patch Management Engine" -or $key.DisplayName -eq "SolarWinds MSP Cache Service") {
   					$temp = $entry.name -replace "HKEY_LOCAL_MACHINE", "HKLM:"
   					$array += $temp
  				}
 			}
		}
	}

	$recurse = Get-ChildItem -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	
	foreach ($entry in $recurse) {
 		foreach ($key in Get-ItemProperty -path "Registry::$entry") {
			if($key.DisplayName -eq "SolarWinds MSP RPC Server" -or $key.DisplayName -eq "Request Handler Agent" -or $key.DisplayName -eq "File Cache Service Agent" -or $key.DisplayName -eq "Patch Management Service Controller" -or $key.DisplayName -eq "SolarWinds MSP Patch Management Engine" -or $key.DisplayName -eq "SolarWinds MSP Cache Service") {
   				$temp = $entry.name -replace "HKEY_LOCAL_MACHINE", "HKLM:"
				$array += $temp
			}
 		}
	}

	foreach ($FolderLocation in $Array) {
		if (Test-Path $FolderLocation) {
			writeToLog I "$FolderLocation exists. Removing item..."
			  
			try {
   				remove-item $folderLocation -recurse -force
  			} catch {
   				writeToLog I "The item $FolderLocation exists but cannot be removed automatically. Please remove manually."
   				$removalError = $error[0]
   				writeToLog E "Exception from removal attempt is: $removalError" 
			}
 		} else {
  			writeToLog W "$FolderLocation doesn't exist - moving on..."
 		}
	}
	writeToLog V ("Completed running {0} function." -f $MyInvocation.MyCommand)
}

function postRuntime() {
	try {
		Remove-Item $scriptLocation -Force -ErrorAction SilentlyContinue
	}
	catch {
	}

	try {
		Remove-Item $xmlLocation -Force -ErrorAction SilentlyContinue
	}
	catch {
	}
}

function writeToLog($state, $message) {

    $script:timestamp = "[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)

	switch -regex -Wildcard ($state) {
		"I" {
			$state = "INFO"
            $colour = "Cyan"
		}
		"E" {
			$state = "ERROR"
            $colour = "Red"
		}
		"W" {
			$state = "WARNING"
            $colour = "Yellow"
		}
		"F"  {
			$state = "FAILURE"
            $colour = "Red"
        }
        "C"  {
			$state = "COMPLETE"
            $colour = "Green"
        }
        "V"  {
            If ($verboseMode -eq $true) {
                $state = "VERBOSE"
                $colour = "Magenta"
            } Else {
                return
            }
		}
		""  {
			$state = "INFO"
		}
		Default {
			$state = "INFO"
		}
     }

    Write-Host "$($timeStamp) - [$state]: $message" -ForegroundColor $colour
    Write-Output "$($timeStamp) - [$state]: $message" | Out-file $logFilePath -Append -ErrorAction SilentlyContinue
}

function main(){
	setupLogging
	validateUserInput
	initialSetup
	downloadXml

	If ($retryXmlDownload -eq $true) {
        installPSServUModule
        downloadSFTPXml
    }

	validateCaseNumber

	getAgentPath
	determinePMEVersion

	If ($legacyPME -eq $true) {
		runPMEV1Uninstaller
	} Else {
		runPMEV2Uninstaller
	}
	
	removeProcesses
    removePMEServices
    removePMEFoldersAndKeys
	
	writeToLog I "PME Cleanup now complete."
	postRuntime
}
main
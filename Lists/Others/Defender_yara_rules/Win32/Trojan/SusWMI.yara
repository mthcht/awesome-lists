rule Trojan_Win32_SusWMI_A_2147954141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWMI.A"
        threat_id = "2147954141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "if((Get-WmiObject -class Win32_ComputerSystem).PartOfDomain)" ascii //weight: 1
        $x_1_3 = "((Get-WmiObject -class Win32_ComputerSystem).Domain)" ascii //weight: 1
        $x_1_4 = "gwmi win32_group -Filter" ascii //weight: 1
        $x_1_5 = "Domain=" ascii //weight: 1
        $n_1_6 = "69802c98-2ca2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Trojan_Win32_SusWMI_B_2147954142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWMI.B"
        threat_id = "2147954142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "[Security.Principal.WindowsIdentity]::GetCurrent()" ascii //weight: 1
        $x_1_3 = "(New-Object Security.Principal.WindowsPrincipal" ascii //weight: 1
        $x_1_4 = "IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)" ascii //weight: 1
        $n_1_5 = "69802c98-2cb2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusWMI_C_2147954143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWMI.C"
        threat_id = "2147954143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe os get" ascii //weight: 1
        $x_1_2 = "lastbootuptime" ascii //weight: 1
        $x_1_3 = "powershell.exe /wInd" ascii //weight: 1
        $x_1_4 = "Get-WmiObject -Class Win32_ComputerSystem" ascii //weight: 1
        $x_1_5 = "powershell.exe -wind hidden" ascii //weight: 1
        $x_1_6 = "cmd.exe /c" ascii //weight: 1
        $x_1_7 = "AppData\\Local\\Temp\\startup_vrun.bat" ascii //weight: 1
        $x_1_8 = "powershell.exe -c" ascii //weight: 1
        $x_1_9 = "Start-Process -WindowStyle hidden -FilePath" ascii //weight: 1
        $n_1_10 = "69802c98-2cc2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_SusWMI_D_2147954144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWMI.D"
        threat_id = "2147954144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject win32_Processor" ascii //weight: 1
        $x_1_3 = "Select NumberOfCores" ascii //weight: 1
        $x_1_4 = "cmd.exe /c" ascii //weight: 1
        $x_1_5 = "timeout" ascii //weight: 1
        $x_1_6 = "/T" wide //weight: 1
        $n_1_7 = "69802c98-2ce2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Trojan_Win32_SusWMI_D_2147954144_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWMI.D"
        threat_id = "2147954144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe" ascii //weight: 1
        $x_1_2 = "Win32_videocontroller" ascii //weight: 1
        $x_1_3 = "adapterram" ascii //weight: 1
        $x_1_4 = "powershell.exe" ascii //weight: 1
        $x_1_5 = "Get-Random -Minimum" ascii //weight: 1
        $x_1_6 = "powershell.exe -c" ascii //weight: 1
        $x_1_7 = "Get-WmiObject win32_ComputerSystem" ascii //weight: 1
        $x_1_8 = "Select TotalPhysicalMemory" ascii //weight: 1
        $x_1_9 = "Get-WmiObject" ascii //weight: 1
        $x_1_10 = "win32_bios" ascii //weight: 1
        $x_1_11 = "Start-Sleep" ascii //weight: 1
        $x_1_12 = "-s" wide //weight: 1
        $x_1_13 = "Unblock-File" ascii //weight: 1
        $x_1_14 = "AppData\\Local\\Temp\\idle_time.ps1" ascii //weight: 1
        $x_1_15 = "ComputerSystem" ascii //weight: 1
        $x_1_16 = "TotalPhysicalMemory" ascii //weight: 1
        $x_1_17 = "OS get" ascii //weight: 1
        $x_1_18 = "FreePhysicalMemory" ascii //weight: 1
        $x_1_19 = "TotalVirtualMemorySize" ascii //weight: 1
        $x_1_20 = "FreeVirtualMemory" ascii //weight: 1
        $x_1_21 = "Win32_Battery" ascii //weight: 1
        $x_1_22 = "BatteryStatus" ascii //weight: 1
        $n_1_23 = "69802c98-2cd2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}


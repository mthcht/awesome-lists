rule Trojan_Win32_SusPrivCheck_A_2147954155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivCheck.A"
        threat_id = "2147954155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivCheck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "Invoke-PrivescCheck" ascii //weight: 1
        $x_1_5 = "Import-Module" ascii //weight: 1
        $n_1_6 = "69802c98-2co2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusPrivCheck_B_2147954156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivCheck.B"
        threat_id = "2147954156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivCheck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "Get-WinUpdates" ascii //weight: 1
        $x_1_5 = "Import-Module" ascii //weight: 1
        $x_1_6 = "-ComputerName localhost" ascii //weight: 1
        $n_1_7 = "69802c98-2cp2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusPrivCheck_C_2147954157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivCheck.C"
        threat_id = "2147954157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivCheck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe query" ascii //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language" ascii //weight: 1
        $n_1_3 = "69802c98-2cq2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusPrivCheck_D_2147954158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivCheck.D"
        threat_id = "2147954158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivCheck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe" ascii //weight: 1
        $x_1_2 = "logicaldisk" ascii //weight: 1
        $x_1_3 = "freespace" ascii //weight: 1
        $x_1_4 = "caption" ascii //weight: 1
        $n_1_5 = "69802c98-2cr2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


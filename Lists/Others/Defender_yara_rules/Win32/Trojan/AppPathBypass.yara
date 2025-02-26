rule Trojan_Win32_AppPathBypass_ZPA_2147934570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AppPathBypass.ZPA"
        threat_id = "2147934570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AppPathBypass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invoke-AppPathBypass" wide //weight: 1
        $x_1_2 = " -Payload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AppPathBypass_ZPB_2147934571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AppPathBypass.ZPB"
        threat_id = "2147934571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AppPathBypass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "DownloadString" wide //weight: 1
        $x_1_3 = "Invoke-AppPathBypass.ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


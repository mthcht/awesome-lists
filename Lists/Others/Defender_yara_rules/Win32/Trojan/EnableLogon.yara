rule Trojan_Win32_EnableLogon_B_2147959775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EnableLogon.B!MTB"
        threat_id = "2147959775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EnableLogon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" wide //weight: 1
        $x_1_2 = "reg add" wide //weight: 1
        $x_1_3 = "/v UseLogonCredential" wide //weight: 1
        $x_1_4 = "/t REG_DWORD /f /d 1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


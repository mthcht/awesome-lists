rule Trojan_Win32_ResAdmin_Z_2147959776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ResAdmin.Z!MTB"
        threat_id = "2147959776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ResAdmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg add" wide //weight: 1
        $x_1_2 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" wide //weight: 1
        $x_1_3 = "/v DisableRestrictedAdmin" wide //weight: 1
        $x_1_4 = "/d 0 /t REG_DWORD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


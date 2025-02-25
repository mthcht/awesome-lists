rule Trojan_Win32_Mikatz_ZPA_2147934396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikatz.ZPA"
        threat_id = "2147934396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sekurlsa" wide //weight: 1
        $x_1_2 = "::minidump" wide //weight: 1
        $x_1_3 = "::logonpassword" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


rule Trojan_Win32_SusNetUser_MK_2147945916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNetUser.MK"
        threat_id = "2147945916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNetUser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "net localgroup & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


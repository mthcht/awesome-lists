rule Trojan_Win32_SusNetShare_MK_2147945915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNetShare.MK"
        threat_id = "2147945915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNetShare"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "net share & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


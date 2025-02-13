rule Trojan_Win32_Seorhick_EA_2147760300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Seorhick.EA"
        threat_id = "2147760300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Seorhick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "facefoduninstaller.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


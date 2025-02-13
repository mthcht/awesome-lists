rule Trojan_Win32_Dukes_BI_2147749932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dukes.BI"
        threat_id = "2147749932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dukes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\WINDOWS\\SYSTEM32\\rundll32.exe C:\\SgIntf.dll,TaskZut" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


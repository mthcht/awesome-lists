rule Trojan_Win32_SusCertutil_A_2147958193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusCertutil.A"
        threat_id = "2147958193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusCertutil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil.exe -decode" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = ".exe" wide //weight: 1
        $x_1_4 = ".txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


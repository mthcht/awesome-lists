rule Trojan_Win32_QakbotDecode_A_2147845984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakbotDecode.A"
        threat_id = "2147845984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakbotDecode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = " -decode " ascii //weight: 10
        $x_10_2 = "\\output.txt" ascii //weight: 10
        $x_10_3 = ".sql" ascii //weight: 10
        $x_2_4 = "certutil" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


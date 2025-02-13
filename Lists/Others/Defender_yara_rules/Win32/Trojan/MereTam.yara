rule Trojan_Win32_MereTam_C_2147741614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MereTam.C"
        threat_id = "2147741614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MereTam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ee 08 8b da 8b ce d3 fb 83 c7 01 85 f6 88 5c 07 ff 75 ec 8b 4c 24 18 83 c5 04 83 e9 01 89 4c 24 18 0f 85 ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ee 08 8b da 8b ce d3 fb 47 85 f6 88 5c 07 ff 75 ee 8b 4c 24 18 83 c5 04 49 89 4c 24 18 0f 85 4a fe ff ff}  //weight: 1, accuracy: High
        $x_10_3 = {56 57 51 8b 74 24 14 8b 7c 24 10 8b 4c 24 18 f3 a4 59 5f 5e c2 0c 00}  //weight: 10, accuracy: High
        $x_10_4 = "C:\\ProgramData\\" wide //weight: 10
        $x_10_5 = "%s\\shell\\open\\%s" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


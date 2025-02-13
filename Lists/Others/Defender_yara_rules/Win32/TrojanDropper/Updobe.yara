rule TrojanDropper_Win32_Updobe_A_2147627865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Updobe.A"
        threat_id = "2147627865"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Updobe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Adobe\\Flash" ascii //weight: 2
        $x_2_2 = "SOFTWARE\\Mozilla\\Firefox\\Extensions" ascii //weight: 2
        $x_2_3 = "191d3f14-ff4c-4895-bdea-db54526cb49a" ascii //weight: 2
        $x_1_4 = {00 69 6e 73 74 61 6c 6c 2e}  //weight: 1, accuracy: High
        $x_1_5 = {00 6f 76 65 72 6c 61 79 2e}  //weight: 1, accuracy: High
        $x_1_6 = {00 67 6f 6f 67 6c 65 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


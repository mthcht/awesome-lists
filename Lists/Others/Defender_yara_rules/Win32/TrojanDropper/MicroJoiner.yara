rule TrojanDropper_Win32_MicroJoiner_C_2147637983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/MicroJoiner.C"
        threat_id = "2147637983"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "MicroJoiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 08 83 c3 ?? 83 ef 01 75 ee 56 ff 15}  //weight: 2, accuracy: Low
        $x_3_2 = {8d 44 3e fc 8b 38 8b cf 6b c9 ?? 53 2b c1 8b d8 51 53 e8}  //weight: 3, accuracy: Low
        $x_1_3 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 80 8d 54 24 20 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


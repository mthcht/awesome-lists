rule TrojanDropper_Win32_Bradop_A_2147651276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bradop.A"
        threat_id = "2147651276"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bradop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c7 06 83 ff 08 7c 55 83 ef 08 8d 45 e8 ba 28 1c}  //weight: 2, accuracy: High
        $x_1_2 = {2e 63 70 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 22}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 4f 50 45 4e 00}  //weight: 1, accuracy: High
        $x_1_4 = "JLfImoX3AK9bKcyX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


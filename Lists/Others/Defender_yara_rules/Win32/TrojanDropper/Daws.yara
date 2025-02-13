rule TrojanDropper_Win32_Daws_B_2147678566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Daws.B"
        threat_id = "2147678566"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Daws"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 73 65 6e 74 70 72 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 66 61 6b 65 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 74 73 68 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {2c 50 72 6f 78 79 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 45 54 44 4c 4c 5f 58 36 34 00}  //weight: 1, accuracy: High
        $x_1_6 = {4e 54 43 4f 4f 4c 00}  //weight: 1, accuracy: High
        $x_5_7 = {b8 4d 5a 00 00 8b 9d 54 ff ff ff 0f b7 0b 3b c8 75 1e db 05 ?? ?? ?? ?? 8b 9d 50 ff ff ff 8b 03 e8 ?? ?? ?? ?? de d9 df e0 9e 0f 84 05 00 00 00 e9 ?? ?? ?? ?? 6a 00 31 c0 8b dc 53 89 03 8b c7 50 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


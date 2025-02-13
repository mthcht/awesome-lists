rule TrojanDropper_Win64_Rotbrow_H_2147684310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Rotbrow.H"
        threat_id = "2147684310"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Rotbrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {24 0f 04 41 88 42 ff 83 f9 40 72 e8 c6 02 00 ff 15 ?? ?? ?? ?? 0f b6 c8 44 8b d8 80 e1 0f 80 c1 41 88 4b 46 8b c8 c1 e9 04 80 e1 0f 80 c1 41 88 4b 47}  //weight: 5, accuracy: Low
        $x_1_2 = {62 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 46 00 6f 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 5f 00 62 00 68 00 6f 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


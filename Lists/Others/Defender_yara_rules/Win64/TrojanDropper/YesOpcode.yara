rule TrojanDropper_Win64_YesOpcode_A_2147978172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/YesOpcode.A!dha"
        threat_id = "2147978172"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "YesOpcode"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 04 80 00 00 45 31 c0 45 31 c9 ff 15 ?? ?? ?? ?? 85 c0 0f 95 44 24 ?? b8 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 10 66 00 00 41 b9 04 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 95 44 24 ?? b8 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_YesOpcode_B_2147978173_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/YesOpcode.B!dha"
        threat_id = "2147978173"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "YesOpcode"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 25 81 50 4c e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 83 2b 50 41 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_FrozenVolcano_B_2147980354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FrozenVolcano.B!dha"
        threat_id = "2147980354"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FrozenVolcano"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 28 41 b8 ?? ?? ?? ?? ba ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 44 89 44 24 18 e9 89 54 24 10}  //weight: 2, accuracy: Low
        $x_1_2 = {48 83 ec 28 41 b8 ?? ?? (01|2d|ff) (01|2d|ff) ba ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 83 c4 28 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {81 bc 24 c0 00 00 00 00 20 00 00 7d}  //weight: 1, accuracy: High
        $x_1_4 = {50 51 59 58 c6 44 24 ?? 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


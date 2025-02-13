rule Trojan_Win64_Gularger_G_2147749584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gularger.G!dha"
        threat_id = "2147749584"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gularger"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 44 24 20 83 c0 01 99 f7 7c 24 58 88 54 24 20 e9 74 ff ff ff 48 83 c4 48 c3}  //weight: 2, accuracy: High
        $x_2_2 = {44 0f b6 5c 24 21 48 8b 44 24 38 42 0f b6 14 18 0f b6 4c 24 20 48 8b 44 24 38 0f b6 0c 08 8b c2 03 c1 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


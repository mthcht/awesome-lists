rule TrojanDropper_Win32_Floxif_A_2147683334_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Floxif.A"
        threat_id = "2147683334"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {66 8b 02 8b 4d 08 03 c8 89 4d 08 8b 55 0c 83 c2 02 89 55 0c 8b 45 08 c1 e8 10 8b 4d 08 81 e1 ff ff 00 00 03 c1 89 45 08}  //weight: 100, accuracy: High
        $x_1_2 = {eb 0f 8b 95 a0 fe ff ff 83 c2 01 89 95 a0 fe ff ff 81 bd a0 fe ff ff 81 0c 00 00 0f 83 9f 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 80 0c 00 00 68 ?? 00 02 10 e8 ?? ?? ff ff 83 c4 08 6a 00 8d 55 f0 52 68 80 0c 00 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


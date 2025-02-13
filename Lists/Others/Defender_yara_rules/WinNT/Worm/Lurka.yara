rule Worm_WinNT_Lurka_A_2147597947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:WinNT/Lurka.A"
        threat_id = "2147597947"
        type = "Worm"
        platform = "WinNT: WinNT"
        family = "Lurka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 bd c0 fe ff ff 50 45 00 00 74 04 6a 03 eb ed 81 bd c8 fe ff ff 00 72 19 1a 75 04 6a 04 eb dd}  //weight: 2, accuracy: High
        $x_2_2 = {c6 45 f4 9c c6 45 f5 e8 e8 ?? ?? ff ff 53 ff 75 ec ff 75 f0 e8 ?? ?? ff ff 3b c3 74 05 6a 02}  //weight: 2, accuracy: Low
        $x_1_3 = {89 45 fc eb 3b c7 45 fc 06 00 00 80 eb 32 33 f6 39 35 ?? ?? 01 00 74 25 8d 45 e8 50 53 ff 75 30 e8 ?? ?? ff ff 84 c0 74 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


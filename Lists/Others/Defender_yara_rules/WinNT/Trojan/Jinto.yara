rule Trojan_WinNT_Jinto_A_2147645525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Jinto.A"
        threat_id = "2147645525"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Jinto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1b c0 83 d8 ff 85 c0 75 ?? 8b 4c 24 0c 0f b7 14 79 89 54 24 1c 47 3b 7c 24 10 72}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 ff 15 ?? ?? ?? ?? 8b f8 33 f6 8d 64 24 00 6a 07 8d 04 3e 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74 ?? 46 81 fe 00 10 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


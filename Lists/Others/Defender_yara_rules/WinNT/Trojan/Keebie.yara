rule Trojan_WinNT_Keebie_A_2147646076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Keebie.A"
        threat_id = "2147646076"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Keebie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 6b c9 3b 03 c1 23 d0 8b 45 f4 0f b7 0c 45 ?? ?? ?? ?? 2b ca}  //weight: 1, accuracy: Low
        $x_1_2 = {99 83 e2 03 03 c2 c1 f8 02 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 81 e1 03 00 00 80 79 ?? 49 83 c9 fc 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


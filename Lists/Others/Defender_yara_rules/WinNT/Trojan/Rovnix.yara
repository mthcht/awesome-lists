rule Trojan_WinNT_Rovnix_A_2147654393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Rovnix.A"
        threat_id = "2147654393"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 42 4f 4f 54 2e 53 59 53 00 [0-48] 56 46 41 54 31 2e 31 20}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 43 04 6a 09 59 bf ?? ?? ?? ?? 8d 70 03 33 d2 f3 a6 c7 45 fc 7b 00 00 c0 0f 85 ?? ?? ?? ?? 8b 75 08 0f b7 50 0b 8b 4e 14 3b d1 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


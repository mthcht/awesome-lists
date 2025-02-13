rule Trojan_WinNT_Whycan_A_2147687016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Whycan.A"
        threat_id = "2147687016"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Whycan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e9 00 20 22 00 0f ?? ?? ?? ?? ?? 83 e9 05 74 ?? 83 e9 06 74 ?? c7 45 d4 32 02 00 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7b 0c 85 ff 0f 84 ?? ?? ?? ?? 80 bf 8a 63 00 00 01 0f 85 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8d b7 a8 2a 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 86 50 14 00 00 8b 4d ?? 8d 1c 31 8b d3 2b d0 0f b7 08 66 89 0c 02}  //weight: 1, accuracy: Low
        $x_1_4 = {8b f3 a5 66 a5 50 a4 e8 ?? ?? ?? ?? 33 c0 8b fb ab 66 ab 5e aa 5b}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b7 07 b9 6e 6b 00 00 66 3b c1 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


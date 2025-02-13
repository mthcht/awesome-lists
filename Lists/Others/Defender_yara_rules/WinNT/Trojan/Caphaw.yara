rule Trojan_WinNT_Caphaw_A_2147682731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Caphaw.A"
        threat_id = "2147682731"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 4d 53 53 2e 45 58 45 00 [0-4] 43 53 52 53 53 2e 45 58 45 00 [0-4] 53 45 52 56 49 43 45 53 2e 45 58 45 00 [0-4] 4c 53 41 53 53 2e 45 58 45 00 [0-4] 53 50 4f 4f 4c 53 56 2e 45 58 45 00 [0-4] 57 49 4e 4c 4f 47 4f 4e 2e 45 58 45 00 [0-4] 53 56 43 48 4f 53 54 2e 45 58 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 0c 8b 51 10 05 7c 04 00 00 c1 e0 05 03 c6 8a 0a 42 88 08 40 84 c9 75 ?? e9 ?? ?? ?? ff 8b 45 0c 8b 35 ?? ?? ?? 00 8b 78 10 83 65 08 00 8d 86 ?? ?? 00 00 89 45 ?? 8b 45 ?? 8d 50 01 8a 08 40 84 c9 75 ?? 8b cf 2b c2 8d 51 01 8a 19 41 84 db 75}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 3f 00 3f 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 [0-6] 5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 73 00 65 00 72 00 76 00 69 00 73 00 65 00 2e 00 73 00 79 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_WinNT_Nagyo_C_2147622920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Nagyo.C!rootkit"
        threat_id = "2147622920"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Nagyo"
        severity = "Critical"
        info = "rootkit: rootkit component of that malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{232f4e3f2-bab8-11d0-97b9-00c04f98bcb9}" wide //weight: 1
        $x_1_2 = "{256dc5e0e-7c46-11d3-b5bf-0000f8695621}" wide //weight: 1
        $x_1_3 = {ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? 01 00 33 c9 3b c1 89 45 10 0f 8c ?? ?? 00 00 81 7d 1c 03 00 12 00 0f 85 ?? ?? 00 00 38 0e}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? 01 00 8b c8 85 c9 89 4d 18 7c 19 8b 45 24 48 74 ?? 48 74 ?? 48 74 ?? 83 e8 09 74 ?? 83 e8 19 74 ?? 48 74 ?? 8b c1 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_WinNT_Nagyo_A_2147639860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Nagyo.A!rootkit"
        threat_id = "2147639860"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Nagyo"
        severity = "Critical"
        info = "rootkit: rootkit component of that malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c 81 39 80 00 00 00 73 61 68 44 64 6b 20 8b 55 f8 52 6a 01 ff 15 ?? ?? ?? ?? 8b 4d 0c 8b 11 8b 4d 08 89 04 91 8b 55 0c 8b 02 8b 4d 08 83 3c 81 00 75 0b 8b 55 14 c7 02 9a 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 04 81 79 18 73 45 72 76 75 0b 8b 55 cc 89 15 ?? ?? ?? ?? eb 05 e9 ?? ?? ff ff 83 3d ?? ?? ?? ?? 00 75 10 ff 15 ?? ?? ?? ?? b8 01 00 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


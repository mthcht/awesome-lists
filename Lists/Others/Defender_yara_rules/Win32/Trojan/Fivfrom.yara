rule Trojan_Win32_Fivfrom_A_2147638817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fivfrom.gen!A"
        threat_id = "2147638817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fivfrom"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 10 a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? b9 03 00 00 00 99 f7 f9 a0 ?? ?? ?? ?? 2a c2 40 a2 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 a8}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ff ff 2f 00 31 c0 83 c0 ?? 50 51 6a 00 e8 ?? ?? ?? ?? 59 58 e2 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 43 01 b9 03 00 00 00 99 f7 f9 8b 45 f8 0f b6 04 18 2b c2 d1 f8 79 03 83 d0 00 5a 88 02 43 4e 75 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Fivfrom_B_2147647502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fivfrom.gen!B"
        threat_id = "2147647502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fivfrom"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 ac 32 05 ?? ?? ?? ?? aa e2 f6}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ff ff 2f 00 31 c0 83 c0 ?? 50 51 6a 00 e8 ?? ?? ?? ?? 59 58 e2 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 ff ff ff ff 8b 45 08 8b 00 83 f8 00 74 07 b9 05 00 00 00 e2 ef fa fa fa fa 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


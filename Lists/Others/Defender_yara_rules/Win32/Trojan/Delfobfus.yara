rule Trojan_Win32_Delfobfus_A_2147605348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfobfus.A"
        threat_id = "2147605348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {85 db 85 db}  //weight: 1, accuracy: High
        $x_1_3 = {85 c9 85 c9}  //weight: 1, accuracy: High
        $x_1_4 = {39 c0 39 c0}  //weight: 1, accuracy: High
        $x_1_5 = {39 c0 39 d2}  //weight: 1, accuracy: High
        $x_1_6 = {85 c0 85 c9}  //weight: 1, accuracy: High
        $x_2_7 = {8a 4c 06 ff 80 f1 2b 32 ca 80 f1 2b 88 4c 06 ff [0-32] 81 fa ff 00 00 00 7d}  //weight: 2, accuracy: Low
        $x_2_8 = {67 64 69 33 32 2e 64 6c 6c 00 00 00 53 65 74 54 65 78 74 43 6f 6c 6f 72 00 00 00 00 47 65 74 54 65 78 74 43 6f 6c 6f 72 00 00 75 73 65 72 33 32 2e 64 6c 6c 00 00 00 00 47 65 74 44 43 00 00 00 00 00 00 00 00}  //weight: 2, accuracy: High
        $x_10_9 = {64 ff 30 64 89 20 0b 00 55 8b ec 33 c0 55 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delfobfus_C_2147606865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delfobfus.C"
        threat_id = "2147606865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 00 02 00 01 00 [0-32] e8 ?? ?? ff ff 84 c0 0f 84 ?? ?? 00 00 [0-16] a1 ?? ?? 40 00 50 a1 ?? ?? 40 00 50 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 04 68 00 30 00 00 a1 ?? ?? 40 00 8b 40 50 50 a1 ?? ?? 40 00 8b 40 34 50 a1 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 68 ?? ?? 40 00}  //weight: 10, accuracy: Low
        $x_2_3 = {8b 07 8a 44 18 ff 34 1c 34 0d 8b f0 81 e6 ff 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {8b 55 f8 8b 4d fc 8b 09 8b 5d f8 8a 4c 19 ff 80 f1 0d 80 f1 1c 88 4c 10 ff}  //weight: 2, accuracy: High
        $x_1_5 = {83 7d f4 21 75 09 c7 45 f4 01 00 00 00 eb 09 83 7d f4 21 74 03 ff 45 f4}  //weight: 1, accuracy: High
        $x_1_6 = {83 fd 21 75 07 bd 01 00 00 00 eb 06 83 fd 21 74 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


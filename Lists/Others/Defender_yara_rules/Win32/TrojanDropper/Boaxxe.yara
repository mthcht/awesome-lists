rule TrojanDropper_Win32_Boaxxe_C_2147603386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Boaxxe.C"
        threat_id = "2147603386"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 bd f0 fd ff ff 00 74 0d 8d 95 f8 fe ff ff 52 ff 15 ?? ?? 40 00 83 7d 14 02 75 75 8d 45 f8 50 8d 8d f8 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Boaxxe_D_2147603387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Boaxxe.D"
        threat_id = "2147603387"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 10 7d 30 8b 45 f4 83 c0 11 6b c0 71 25 ff 00 00 00 89 45 f4 8a 4d f4 88 4d fc 8b 55 08 03 55 f8 0f be 02 0f be 4d fc 33 c1 8b 55 0c 03 55 f8 88 02 eb bf}  //weight: 1, accuracy: High
        $x_1_2 = {eb 09 8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 10 7d 41 51 8b 45 f4 b9 11 00 00 00 03 c1 81 c1 48 04 00 00 0f af c1 25 ff ff 01 00 89 45 f4 59 8b 45 f4 25 ff 00 00 00 88 45 fc 8b 4d 08 03 4d f8 0f be 11 0f be 45 fc 33 d0 8b 4d 0c 03 4d f8 88 11 eb ae}  //weight: 1, accuracy: High
        $x_1_3 = {89 85 f0 fd ff ff 83 bd f0 fd ff ff 00 74 16 83 3d ?? ?? ?? 00 00 74 0d 8d 85 f8 fe ff ff 50 ff 15 ?? ?? ?? 00 83 7d (10|14) 02 0f 85 ?? 00 00 00 6a 20 8d 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Boaxxe_E_2147621052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Boaxxe.E"
        threat_id = "2147621052"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 11 8b 45 f8 c1 e8 03 25 ff 00 00 00 0f be c8 33 d1 8b 45 ?? 03 45 fc 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {73 09 c7 45 f4 ?? 00 00 00 eb 07 c7 45 f4 ?? 00 00 00 81 7d f8 ?? ?? 00 00 76 07 c7 45 f4 ?? 00 00 00 83 7d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Boaxxe_G_2147626928_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Boaxxe.G"
        threat_id = "2147626928"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {35 aa 55 c3 01 50 [0-8] e8 ?? ?? ff ff [0-8] 02 c3 fa 13}  //weight: 10, accuracy: Low
        $x_10_2 = {35 02 c3 fa 13 [0-6] 81 f2 aa 55 c3 01 [0-8] e8}  //weight: 10, accuracy: Low
        $x_1_3 = {8b 40 3c 83 c0 14 05 e0 00 00 00 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


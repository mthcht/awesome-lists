rule Trojan_Win64_CannonLoader_A_2147955247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CannonLoader.A"
        threat_id = "2147955247"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CannonLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 04 db 8b c8 c1 e9 0b 33 c8 69 c1 01 80 00 00 3d 5a c1 7d 36}  //weight: 2, accuracy: High
        $x_2_2 = {65 48 8b 04 25 60 00 00 00 4c 8b 70 18 49 83 c6 20 49 8b 3e 49 3b fe}  //weight: 2, accuracy: High
        $x_2_3 = {c7 44 24 20 b8 0b 00 00 48 8b d0 48 c7 44 24 50 00 00 00 00 ff d5 85 c0}  //weight: 2, accuracy: High
        $x_1_4 = {68 66 93 11}  //weight: 1, accuracy: High
        $x_1_5 = {d4 3d 2c 61}  //weight: 1, accuracy: High
        $x_1_6 = {2d a0 dc 47}  //weight: 1, accuracy: High
        $x_1_7 = {ba 00 9a fd 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


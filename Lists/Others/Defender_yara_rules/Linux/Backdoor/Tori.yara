rule Backdoor_Linux_Tori_A_2147828131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tori.A!xp"
        threat_id = "2147828131"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tori"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 49 c7 c0 50 3b 40 00 48 c7 c1 e0 3a 40 00 48 c7 c7 40 11 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 ff 72 61 00 55 48 2d f8 72 61 00 48 83 f8 0e 48 89 e5 76 1b b8 00 00 00 00 48 85 c0 74 11 5d bf f8 72 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tori_B_2147828132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tori.B!xp"
        threat_id = "2147828132"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tori"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 50 e2 05 10 a0 e1 03 20 a0 e1 06 00 a0 e1 03 40 84 e0 ef}  //weight: 1, accuracy: High
        $x_1_2 = {30 9a e5 07 01 84 e7 01 70 87 e2 07 00 53 e1 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


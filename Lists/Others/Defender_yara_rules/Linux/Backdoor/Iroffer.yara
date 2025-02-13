rule Backdoor_Linux_Iroffer_A_2147830598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Iroffer.A!xp"
        threat_id = "2147830598"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Iroffer"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 08 8b 75 0c e8 74 c5 00 00 83 c4 f8 56 53 e8 92 00 00 00 83 c4 10 83 f8 01 74 0e 7e 4e 83 f8 02 74 3a 83 f8 03}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 f8 ff 36 68 40 01 07 08 e8 05 60 ff ff 83 c4 f4 6a 00}  //weight: 1, accuracy: High
        $x_1_3 = {a1 90 9c 07 08 31 c9 29 c3 39 d9 7d 1f bf 54 a5 07 08 8d 14 86}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


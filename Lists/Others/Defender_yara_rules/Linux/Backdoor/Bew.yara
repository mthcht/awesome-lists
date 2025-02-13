rule Backdoor_Linux_Bew_A_2147824589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Bew.A!xp"
        threat_id = "2147824589"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Bew"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 4c 24 04 83 e4 f0 ff 71 fc 55 89 e5 57 56 53 51 81 ec 14 0d 00 00 8b 41 04}  //weight: 1, accuracy: High
        $x_1_2 = {8a 54 5e 01 8d 42 d0 3c 09 76 16 8d 42 9f 3c 05 77 05 8d 42 a9}  //weight: 1, accuracy: High
        $x_1_3 = {8a 14 03 84 d2 75 f5 c6 04 01 00 5b 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


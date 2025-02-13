rule Backdoor_Linux_Sshdkit_C_2147825988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Sshdkit.C!xp"
        threat_id = "2147825988"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Sshdkit"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 3a 74 10 ff c1 48 83 c2 04 81 f9 80 00 00 00 75 ee 30 c9}  //weight: 1, accuracy: High
        $x_1_2 = {66 83 3f 0a 48 89 fa 75 3b 83 7f 08 00 75 35 83 7f 0c 00 75 2f 81 7f 10 00 00 ff ff 75 26 44 8b 4f 14 66 44 8b 47 02 b9 04 00 00 00 31 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


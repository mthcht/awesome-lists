rule Backdoor_Linux_Rekobee_2147773042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Rekobee"
        threat_id = "2147773042"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Rekobee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c6 00 2f c6 40 04 2f c6 40 01 62 (c6 40|48 8d 70 05 c6) [0-5] c6 40 02 69 c6 40 06 68 [0-3] c6 40 03 6e c6 40 07 00 [0-23] e8}  //weight: 4, accuracy: Low
        $x_1_2 = {be 14 54 00 00 31 01 be e8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 14 54 00 00 [0-49] e8}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 04 14 54 00 00 [0-49] e8}  //weight: 1, accuracy: Low
        $x_4_5 = {c6 00 48 c6 40 05 49 c6 40 01 49 c6 40 06 4c c6 40 02 53 c6 40 07 45 c6 40 03 54 c6 40 08 3d c6 40 04 46 c6 40 09 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}


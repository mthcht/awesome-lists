rule Worm_Linux_Kork_A_2147828980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Linux/Kork.A!xp"
        threat_id = "2147828980"
        type = "Worm"
        platform = "Linux: Linux platform"
        family = "Kork"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "t:r:c:a:o:p:w:k" ascii //weight: 1
        $x_1_2 = "SEClpd victim" ascii //weight: 1
        $x_1_3 = {76 69 63 74 69 6d [0-4] 62 72 75 74 65 [0-4] 2d 74 20 74 79 70 65 20 5b 2d 6f 20 6f 66 66 73 65 74 5d}  //weight: 1, accuracy: Low
        $x_1_4 = "LPRng/lpd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


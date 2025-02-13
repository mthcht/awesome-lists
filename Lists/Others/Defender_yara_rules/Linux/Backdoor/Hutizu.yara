rule Backdoor_Linux_Hutizu_A_2147819515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Hutizu.A!xp"
        threat_id = "2147819515"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Hutizu"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UDPATTACK" ascii //weight: 1
        $x_1_2 = {8d b6 00 00 00 00 8d 42 01 a3 24 0c 0f 08 ff 14 85 1c e0 0e 08 8b 15 24 0c 0f 08 39 da 72 e7}  //weight: 1, accuracy: High
        $x_1_3 = {b8 b0 81 05 08 85 c0 74 0c c7 04 24 54 29 0e 08 e8 d2 ff 00 00 c6 05 20 0c 0f 08 01}  //weight: 1, accuracy: High
        $x_1_4 = {00 c7 44 24 04 5c 98 0c 08 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


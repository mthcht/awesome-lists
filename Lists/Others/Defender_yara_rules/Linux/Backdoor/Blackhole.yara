rule Backdoor_Linux_Blackhole_B_2147795448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Blackhole.B!xp"
        threat_id = "2147795448"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Blackhole"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f4 60 89 04 08 c7 45 f0 80 89 04 08 c7 45 ec c0 89 04 08 66 c7 45 c8 02 00 83 ec 0c 68 39 30 00 00 e8 e8 fe ff ff 83 c4 10 66 89 45 ca c7 45 cc 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "I_did_not_change_HIDE" ascii //weight: 1
        $x_1_3 = {53 6f 63 6b 65 74 20 65 72 72 6f 72 0a 00 42 69 6e 64 20 65 72 72 6f 72 0a 00 4c 69 73 74 65 6e 20 65 72 72 6f 72 0a 00 41 63 63 65 70 74 20 65 72 72 6f 72 00 2f 62 69 6e 2f 73 68 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


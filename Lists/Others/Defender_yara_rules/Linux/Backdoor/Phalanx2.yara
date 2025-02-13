rule Backdoor_Linux_Phalanx2_A_2147826658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Phalanx2.A!xp"
        threat_id = "2147826658"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Phalanx2"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/dev/shm/%s.injected" ascii //weight: 1
        $x_1_2 = "setenforce 0 2>/dev/null" ascii //weight: 1
        $x_1_3 = "tcp4_seq_show.." ascii //weight: 1
        $x_1_4 = ":O 0x%lx seems fucken large" ascii //weight: 1
        $x_1_5 = {74 12 b8 00 00 00 00 85 c0 74 09 c7 04 24 28 00 0d 08 ff d0}  //weight: 1, accuracy: High
        $x_1_6 = {8b 00 0f b6 00 3c 64 75 0e c7 04 24 ac 0d 0b 08 e8 06 91 00 00 eb 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


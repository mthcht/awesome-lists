rule Backdoor_Linux_Rivl_A_2147827557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Rivl.A!xp"
        threat_id = "2147827557"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Rivl"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Privl:" ascii //weight: 1
        $x_1_2 = "synspoofflood" ascii //weight: 1
        $x_1_3 = "updatebots" ascii //weight: 1
        $x_1_4 = "tcpreject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


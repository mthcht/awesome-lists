rule Backdoor_Linux_Ibiru_A_2147827550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Ibiru.A!xp"
        threat_id = "2147827550"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Ibiru"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sapibiru" ascii //weight: 1
        $x_1_2 = "kFbind" ascii //weight: 1
        $x_1_3 = "Fuck Off This Machine" ascii //weight: 1
        $x_1_4 = "Paranoia Secret" ascii //weight: 1
        $x_1_5 = "bindary.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


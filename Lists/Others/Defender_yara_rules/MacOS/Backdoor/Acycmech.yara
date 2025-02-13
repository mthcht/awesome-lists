rule Backdoor_MacOS_Acycmech_A_2147814036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Acycmech.A!xp"
        threat_id = "2147814036"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Acycmech"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/confs/bot%u.conf" ascii //weight: 1
        $x_1_2 = "Acycmech Bot %d Config" ascii //weight: 1
        $x_1_3 = "www.cycomm-lamm3rz.b0x.ro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


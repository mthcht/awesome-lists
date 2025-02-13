rule Trojan_Linux_Mircforce_A_2147819263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mircforce.A!xp"
        threat_id = "2147819263"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mircforce"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tHE:mIRKfORCE" ascii //weight: 1
        $x_2_2 = "s/ircnet/mirknet/" ascii //weight: 2
        $x_1_3 = "def.flood" ascii //weight: 1
        $x_1_4 = "RAW iRCLiNE" ascii //weight: 1
        $x_1_5 = ".:tHa lEEtf0rCe:." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


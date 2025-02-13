rule Virus_Linux_Ovets_A_2147827724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Linux/Ovets.A!xp"
        threat_id = "2147827724"
        type = "Virus"
        platform = "Linux: Linux platform"
        family = "Ovets"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hacknix.asm" ascii //weight: 1
        $x_1_2 = "try to infect" ascii //weight: 1
        $x_1_3 = "[hAckniX <@))>< PienSteVo]L" ascii //weight: 1
        $x_1_4 = "first balroged pgm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


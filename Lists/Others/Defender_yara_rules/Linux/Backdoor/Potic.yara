rule Backdoor_Linux_Potic_A_2147827551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Potic.A!xp"
        threat_id = "2147827551"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Potic"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "psotnic-0.2.5" ascii //weight: 1
        $x_1_2 = "Bots on-line" ascii //weight: 1
        $x_1_3 = "psotnic*.tar.gz" ascii //weight: 1
        $x_1_4 = ".bots [expr] [flags] .status [bot]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


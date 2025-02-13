rule Backdoor_Linux_Dobrang_A_2147827547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Dobrang.A!xp"
        threat_id = "2147827547"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Dobrang"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ranzou: invalid port number." ascii //weight: 1
        $x_1_2 = "ranzou --help" ascii //weight: 1
        $x_1_3 = "/bin/sh -i" ascii //weight: 1
        $x_1_4 = "Going in the background" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


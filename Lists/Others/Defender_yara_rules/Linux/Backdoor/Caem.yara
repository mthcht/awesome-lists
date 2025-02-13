rule Backdoor_Linux_Caem_A_2147828983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Caem.A!xp"
        threat_id = "2147828983"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Caem"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alf.eXp.Dimulai" ascii //weight: 1
        $x_1_2 = "Datang Di eXploit Shell" ascii //weight: 1
        $x_1_3 = "dengan pid" ascii //weight: 1
        $x_1_4 = "alf.eXploit.shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


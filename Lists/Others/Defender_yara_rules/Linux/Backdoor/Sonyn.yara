rule Backdoor_Linux_Sonyn_A_2147828979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Sonyn.A!xp"
        threat_id = "2147828979"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Sonyn"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chmod +x update.sh" ascii //weight: 1
        $x_1_2 = "tar cvzf /tmp/doc.tar.gz" ascii //weight: 1
        $x_1_3 = "1000:/loot" ascii //weight: 1
        $x_1_4 = "./exec.sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


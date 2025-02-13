rule Trojan_Linux_Vlany_A_2147826926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Vlany.A!xp"
        threat_id = "2147826926"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Vlany"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hide_vlany" ascii //weight: 1
        $x_1_2 = "hidden_ports" ascii //weight: 1
        $x_1_3 = "/tmp/.XXH" ascii //weight: 1
        $x_1_4 = "unhide_proc" ascii //weight: 1
        $x_1_5 = "/proc/*/numa_maps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Linux_Sniff_A_2147827723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sniff.A!xp"
        threat_id = "2147827723"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sniff"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/var/tmp/.fs_rep_sn.log" ascii //weight: 1
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "RESSDATECMDSCOMPMODR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Linux_Hydgo_A_2147818618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Hydgo.A!xp"
        threat_id = "2147818618"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Hydgo"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hydrogen_client [-l port]" ascii //weight: 2
        $x_2_2 = "hclient_loop.c" ascii //weight: 2
        $x_1_3 = "pf_start_out_tcp" ascii //weight: 1
        $x_1_4 = "/tmp/hlog.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


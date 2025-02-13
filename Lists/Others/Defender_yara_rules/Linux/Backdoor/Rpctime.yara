rule Backdoor_Linux_Rpctime_A_2147830768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Rpctime.A!xp"
        threat_id = "2147830768"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Rpctime"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xdr_long" ascii //weight: 1
        $x_1_2 = "xdr_wrapstring" ascii //weight: 1
        $x_1_3 = "RPC TIME BACKDOOR" ascii //weight: 1
        $x_1_4 = "DEADH0UR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


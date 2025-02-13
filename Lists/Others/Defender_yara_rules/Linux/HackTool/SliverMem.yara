rule HackTool_Linux_SliverMem_A_2147916515_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SliverMem.A!!SliverMem.A"
        threat_id = "2147916515"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SliverMem"
        severity = "High"
        info = "SliverMem: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sliverpb" ascii //weight: 3
        $x_1_2 = "Beacon" ascii //weight: 1
        $x_1_3 = "Register.Jitter" ascii //weight: 1
        $x_1_4 = "Register.NextCheckin" ascii //weight: 1
        $x_1_5 = "OpenSession.C2s" ascii //weight: 1
        $x_1_6 = "InvokeSpawnDll" ascii //weight: 1
        $x_1_7 = "SockTabEntry" ascii //weight: 1
        $x_1_8 = "RportFwdListener" ascii //weight: 1
        $x_1_9 = "MemfilesRm" ascii //weight: 1
        $x_1_10 = "TunnelID" ascii //weight: 1
        $x_1_11 = "BeaconTasks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}


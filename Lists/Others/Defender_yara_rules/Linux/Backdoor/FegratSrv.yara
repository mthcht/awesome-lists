rule Backdoor_Linux_FegratSrv_A_2147770262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/FegratSrv.A!dha"
        threat_id = "2147770262"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "FegratSrv"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RedFlare/gorat_server.Config" ascii //weight: 1
        $x_1_2 = "RedFlare/gorat_server.(*Server).getGoRatBinary" ascii //weight: 1
        $x_1_3 = "RedFlare/gorat_server.HTTPProxyServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_FegratSrv_B_2147770263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/FegratSrv.B!dha"
        threat_id = "2147770263"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "FegratSrv"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RedFlare/RedFlare/server/payloadgen.backends" ascii //weight: 1
        $x_1_2 = "RedFlare/RedFlare/server/deploy/provisioners/gorat.runShell" ascii //weight: 1
        $x_1_3 = "RedFlare/RedFlare/server/storage/postgres.initialBeaconDurCheck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


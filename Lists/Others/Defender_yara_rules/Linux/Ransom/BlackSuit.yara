rule Ransom_Linux_BlackSuit_A_2147846362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BlackSuit.A!MTB"
        threat_id = "2147846362"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BlackSuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README.BlackSuit.txt" ascii //weight: 1
        $x_1_2 = ".blacksuit_log_" ascii //weight: 1
        $x_1_3 = "esxcli vm process kill --type=force --world-id" ascii //weight: 1
        $x_1_4 = "esxcli vm process list > PID_list" ascii //weight: 1
        $x_1_5 = "ps -Cc|grep vmsyslogd > PS_syslog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


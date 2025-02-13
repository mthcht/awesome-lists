rule Backdoor_MacOS_GoDoor_A_2147899716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/GoDoor.A!MTB"
        threat_id = "2147899716"
        type = "Backdoor"
        platform = "MacOS: "
        family = "GoDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.sendFileToMythic" ascii //weight: 1
        $x_1_2 = "GetFileFromMythic" ascii //weight: 1
        $x_1_3 = "main.aggregateDelegateMessagesToMythic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_GoDoor_B_2147927640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/GoDoor.B!MTB"
        threat_id = "2147927640"
        type = "Backdoor"
        platform = "MacOS: "
        family = "GoDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.goShell" ascii //weight: 2
        $x_2_2 = "net.goLookupPort" ascii //weight: 2
        $x_2_3 = "main.persistence" ascii //weight: 2
        $x_1_4 = "ReverseGoShell-master/src/client_Mac_re1.go" ascii //weight: 1
        $x_1_5 = "/root/malware/malwareKiller.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


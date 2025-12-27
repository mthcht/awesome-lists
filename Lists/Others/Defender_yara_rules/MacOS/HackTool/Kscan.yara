rule HackTool_MacOS_Kscan_A_2147951884_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Kscan.A!MTB"
        threat_id = "2147951884"
        type = "HackTool"
        platform = "MacOS: "
        family = "Kscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kscan/core/hydra/redis.readResponse" ascii //weight: 1
        $x_1_2 = "kscan/core/hydra.rdpCracker" ascii //weight: 1
        $x_1_3 = "kscan/core/hydra/ssh.Check" ascii //weight: 1
        $x_1_4 = "kscan/core/spy.dnsTesting" ascii //weight: 1
        $x_1_5 = "kscan/core/spy.HostDiscoveryIcmpPool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


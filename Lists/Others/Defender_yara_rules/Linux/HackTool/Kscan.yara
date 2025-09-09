rule HackTool_Linux_Kscan_A_2147951883_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Kscan.A!MTB"
        threat_id = "2147951883"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Kscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kscan/core/hydra/redis.readResponse" ascii //weight: 1
        $x_1_2 = "kscan/core/scanner.NewURLScanner" ascii //weight: 1
        $x_1_3 = "kscan/core/scanner.NewHydraScanner" ascii //weight: 1
        $x_1_4 = "kscan/core/scanner.(*IPClient).Push" ascii //weight: 1
        $x_1_5 = "kscan/core/hydra.(*Cracker).success" ascii //weight: 1
        $x_1_6 = "kscan/core/spy.HostDiscoveryIcmpPool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


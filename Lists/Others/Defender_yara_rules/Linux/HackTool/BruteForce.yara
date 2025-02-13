rule HackTool_Linux_BruteForce_A_2147926123_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/BruteForce.A!MTB"
        threat_id = "2147926123"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "BruteForce"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "masjesuscan/exploit/sshscan.Brutessh" ascii //weight: 1
        $x_1_2 = "exploit/envscan.GetWebasshttp" ascii //weight: 1
        $x_1_3 = "/root/masjesu/scan/exploit/tplink/main.go" ascii //weight: 1
        $x_1_4 = "masjesuscan/exploit/tplink.Cve20231389" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


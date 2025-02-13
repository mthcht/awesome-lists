rule HackTool_Linux_Ruler_A_2147891977_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Ruler.A!MTB"
        threat_id = "2147891977"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Ruler"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autodiscover.BruteForce" ascii //weight: 1
        $x_1_2 = "/dev/ruler/ruler.go" ascii //weight: 1
        $x_1_3 = "/rpc-http/packets.go" ascii //weight: 1
        $x_1_4 = "github.com/sensepost/ruler/mapi.ExecuteMailRuleAdd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


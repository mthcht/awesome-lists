rule HackTool_MacOS_Ruler_B_2147892067_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Ruler.B!MTB"
        threat_id = "2147892067"
        type = "HackTool"
        platform = "MacOS: "
        family = "Ruler"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/sensepost/ruler/mapi" ascii //weight: 1
        $x_1_2 = "ruler/rpc-http/packets.go" ascii //weight: 1
        $x_1_3 = "autodiscover/brute.go" ascii //weight: 1
        $x_1_4 = "/ruler/autodiscover.UserPassBruteForce" ascii //weight: 1
        $x_1_5 = "*tls.clientKeyExchangeMsg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


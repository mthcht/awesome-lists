rule HackTool_MacOS_ConScan_A_2147929989_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/ConScan.A!MTB"
        threat_id = "2147929989"
        type = "HackTool"
        platform = "MacOS: "
        family = "ConScan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tool/probe.ScanPort" ascii //weight: 1
        $x_1_2 = "/pkg/plugin.RunSingleExploit" ascii //weight: 1
        $x_1_3 = "github.com/cdk-team/CDK/pkg/exploit" ascii //weight: 1
        $x_1_4 = "/tool/probe.TCPScanExploitAPI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


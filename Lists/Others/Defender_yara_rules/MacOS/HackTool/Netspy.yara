rule HackTool_MacOS_Netspy_A_2147905470_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Netspy.A!MTB"
        threat_id = "2147905470"
        type = "HackTool"
        platform = "MacOS: "
        family = "Netspy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netspy/core/spy.Spy" ascii //weight: 1
        $x_1_2 = "netspy/core/spy.goSpy" ascii //weight: 1
        $x_1_3 = "netspy/core/arp.checkOs" ascii //weight: 1
        $x_1_4 = "/netspy/cmd/netspy/main.go" ascii //weight: 1
        $x_1_5 = "netspy/core/ping.Spy" ascii //weight: 1
        $x_1_6 = "netspy/core/spy.genAllCIDR" ascii //weight: 1
        $x_1_7 = "go_package/netspy/core/spy/spy.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


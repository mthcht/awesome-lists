rule HackTool_MacOS_ZapTool_A_2147756803_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/ZapTool.A!MTB"
        threat_id = "2147756803"
        type = "HackTool"
        platform = "MacOS: "
        family = "ZapTool"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MassConnectorController beginAttack:" ascii //weight: 1
        $x_1_2 = "sendData" ascii //weight: 1
        $x_1_3 = "/Hacking/My Programs/Source/Cocoa/ZapAttack/" ascii //weight: 1
        $x_1_4 = "UDPFlooderController.h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


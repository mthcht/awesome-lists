rule Trojan_MacOS_PasivRobber_C_2147943464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PasivRobber.C!MTB"
        threat_id = "2147943464"
        type = "Trojan"
        platform = "MacOS: "
        family = "PasivRobber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WXRobber" ascii //weight: 1
        $x_1_2 = "com.myam.plist" ascii //weight: 1
        $x_1_3 = "GetScreenShot" ascii //weight: 1
        $x_1_4 = "libIMKeyTool" ascii //weight: 1
        $x_1_5 = "RemoteMsgManager" ascii //weight: 1
        $x_1_6 = "GetClipboardInfos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


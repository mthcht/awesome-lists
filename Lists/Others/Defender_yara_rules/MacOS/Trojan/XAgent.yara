rule Trojan_MacOS_XAgent_A_2147745269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XAgent.A!MTB"
        threat_id = "2147745269"
        type = "Trojan"
        platform = "MacOS: "
        family = "XAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenShot takeScreenShot" ascii //weight: 1
        $x_1_2 = "InjectApp injectRunningApp" ascii //weight: 1
        $x_1_3 = "BootXLoader injectApplication" ascii //weight: 1
        $x_1_4 = "Password getFirefoxPassword" ascii //weight: 1
        $x_1_5 = "apple-search.info" ascii //weight: 1
        $x_1_6 = {56 0e 9f f0 eb 98 43}  //weight: 1, accuracy: High
        $x_1_7 = "XAgentOSX/XAgentOSX/Source/Boot" ascii //weight: 1
        $x_1_8 = "Keylogger pressedKeyWithKeyCode:andModifiers:" ascii //weight: 1
        $x_1_9 = "RemoteShell executeShellCommand:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


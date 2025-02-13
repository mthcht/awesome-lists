rule Backdoor_iPhoneOS_EggShell_B_2147747948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:iPhoneOS/EggShell.B!MTB"
        threat_id = "2147747948"
        type = "Backdoor"
        platform = "iPhoneOS: "
        family = "EggShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.sysserver" ascii //weight: 2
        $x_2_2 = "commandWithReply:withUserInfo:" ascii //weight: 2
        $x_2_3 = "commandWithNoReply:withUserInfo:" ascii //weight: 2
        $x_2_4 = "attemptUnlockWithPasscode:" ascii //weight: 2
        $x_1_5 = "locationon" ascii //weight: 1
        $x_1_6 = "lastapp" ascii //weight: 1
        $x_1_7 = "ismuted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_iPhoneOS_EggShell_C_2147748000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:iPhoneOS/EggShell.C!MTB"
        threat_id = "2147748000"
        type = "Backdoor"
        platform = "iPhoneOS: "
        family = "EggShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Library/LaunchAgents/.espl.plist" ascii //weight: 1
        $x_1_2 = "[espl openApp:]" ascii //weight: 1
        $x_1_3 = "/tmp/.avatmp" ascii //weight: 1
        $x_1_4 = "getFullCMD" ascii //weight: 1
        $x_1_5 = "takePicture:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_iPhoneOS_EggShell_A_2147748052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:iPhoneOS/EggShell.A!MTB"
        threat_id = "2147748052"
        type = "Backdoor"
        platform = "iPhoneOS: "
        family = "EggShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eggshellPro" ascii //weight: 1
        $x_1_2 = "takeOrderAndReply:withUserInfo:" ascii //weight: 1
        $x_1_3 = "com.sysserver" ascii //weight: 1
        $x_1_4 = "attemptUnlockWithPasscode:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_iPhoneOS_EggShell_D_2147753607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:iPhoneOS/EggShell.D!MTB"
        threat_id = "2147753607"
        type = "Backdoor"
        platform = "iPhoneOS: "
        family = "EggShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EggShell/source-esplosx/esplosx/espl.h" ascii //weight: 2
        $x_1_2 = "/tmp/.avatmp" ascii //weight: 1
        $x_1_3 = "espl ddos:" ascii //weight: 1
        $x_1_4 = "decrypt file.aes password1234" ascii //weight: 1
        $x_1_5 = "getcapturedevice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


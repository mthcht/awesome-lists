rule Misleading_MacOS_BlueBlood_A_324178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/BlueBlood.A!xp"
        threat_id = "324178"
        type = "Misleading"
        platform = "MacOS: "
        family = "BlueBlood"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BrowserInjectorExt.bundle" ascii //weight: 2
        $x_1_2 = "tmp/FlexiSPY" ascii //weight: 1
        $x_1_3 = "mach_inject_bundle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_MacOS_BlueBlood_B_324394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/BlueBlood.B!xp"
        threat_id = "324394"
        type = "Misleading"
        platform = "MacOS: "
        family = "BlueBlood"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "blbla launching args : %@" ascii //weight: 2
        $x_1_2 = "makara@digitalendpoint.com" ascii //weight: 1
        $x_1_3 = "com.applle.blbla" ascii //weight: 1
        $x_1_4 = "BlueBlood/blbla/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Misleading_MacOS_BlueBlood_C_324395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/BlueBlood.C!xp"
        threat_id = "324395"
        type = "Misleading"
        platform = "MacOS: "
        family = "BlueBlood"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UAMAManager startActivityMonitor" ascii //weight: 1
        $x_1_2 = "/Backup/FlexiSPY" ascii //weight: 1
        $x_1_3 = "com.applle.UserActivityMonitorAgentUI" ascii //weight: 1
        $x_1_4 = "UserActivityCaptureManager/UserActivityMonitorAgent" ascii //weight: 1
        $x_1_5 = "com.applle.UAMA.logoutContinued" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Misleading_MacOS_BlueBlood_D_329712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/BlueBlood.D!xp"
        threat_id = "329712"
        type = "Misleading"
        platform = "MacOS: "
        family = "BlueBlood"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DaemonPrivateHome.m" ascii //weight: 1
        $x_2_2 = "/Library/Developer/Xcode/DerivedData/blblu-" ascii //weight: 2
        $x_1_3 = "[ScreenshotUtils takeScreenShotWithScreen:" ascii //weight: 1
        $x_1_4 = "killProcessWithProcessName:" ascii //weight: 1
        $x_1_5 = "getSysInfoIntByName" ascii //weight: 1
        $x_1_6 = "/UserActivityCaptureManager.build" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Misleading_MacOS_BlueBlood_E_341497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/BlueBlood.E!xp"
        threat_id = "341497"
        type = "Misleading"
        platform = "MacOS: "
        family = "BlueBlood"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "BrowserInjectorExt" ascii //weight: 2
        $x_1_2 = "FlexiSPY" ascii //weight: 1
        $x_1_3 = "MessagePortIPCSender.h" ascii //weight: 1
        $x_1_4 = {62 6c 62 6c 75 2d 20 2f 42 75 69 6c 64 2f 50 72 6f 64 75 63 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


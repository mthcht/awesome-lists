rule HackTool_MacOS_Vortex_D_2147832207_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Vortex.D!MTB"
        threat_id = "2147832207"
        type = "HackTool"
        platform = "MacOS: "
        family = "Vortex"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 4f 64 79 73 73 65 79 2f 4f 64 79 73 73 65 79 2f 65 78 70 6c 6f 69 74 [0-21] 2e 63}  //weight: 1, accuracy: Low
        $x_1_2 = "/odyssey/launchjailbreak" ascii //weight: 1
        $x_1_3 = "/odyssey/amfidebilitate.plist" ascii //weight: 1
        $x_1_4 = "org.coolstar.jailbreakd" ascii //weight: 1
        $x_1_5 = "RRRReatrmpe 9afioasf" ascii //weight: 1
        $x_1_6 = "tfp0" ascii //weight: 1
        $x_1_7 = "tardy0n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


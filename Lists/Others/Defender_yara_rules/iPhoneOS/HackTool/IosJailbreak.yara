rule HackTool_iPhoneOS_iOSJailbreak_AA_2147833632_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:iPhoneOS/iOSJailbreak.AA!MTB"
        threat_id = "2147833632"
        type = "HackTool"
        platform = "iPhoneOS: "
        family = "iOSJailbreak"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "update.93.pangu.io/jb" ascii //weight: 1
        $x_1_2 = "/tmp/.pangu93loaded" ascii //weight: 1
        $x_1_3 = "io.pangu93.loader.plist" ascii //weight: 1
        $x_1_4 = "cydia://" ascii //weight: 1
        $x_1_5 = "com.saurik.cydia" ascii //weight: 1
        $x_1_6 = "io.pangu.nvwastone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_iPhoneOS_iOSJailbreak_AB_2147833633_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:iPhoneOS/iOSJailbreak.AB!MTB"
        threat_id = "2147833633"
        type = "HackTool"
        platform = "iPhoneOS: "
        family = "iOSJailbreak"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runJailbreakd.js" ascii //weight: 1
        $x_1_2 = "launchKernelExploit.js" ascii //weight: 1
        $x_1_3 = "/LinusHenze/Fugu14/blob" ascii //weight: 1
        $x_1_4 = "JailbreakUtils/MachOFiletype.swift" ascii //weight: 1
        $x_1_5 = "ClosureInjection" ascii //weight: 1
        $x_1_6 = "FuguApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


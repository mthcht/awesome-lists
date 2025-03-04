rule HackTool_iPhoneOS_IosJailbreak_A_2147837256_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:iPhoneOS/IosJailbreak.A!MTB"
        threat_id = "2147837256"
        type = "HackTool"
        platform = "iPhoneOS: "
        family = "IosJailbreak"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users/pwned4/Downloads/Th0r_Freya-main/TH0R/exploits" ascii //weight: 1
        $x_1_2 = "shogunpwnd" ascii //weight: 1
        $x_1_3 = "/var/run/pspawn_hook.ts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_iPhoneOS_IosJailbreak_B_2147840761_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:iPhoneOS/IosJailbreak.B!MTB"
        threat_id = "2147840761"
        type = "HackTool"
        platform = "iPhoneOS: "
        family = "IosJailbreak"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hooking Payload" ascii //weight: 1
        $x_1_2 = "OneLol1n" ascii //weight: 1
        $x_1_3 = "/pprivar/mbrary/Carivaate/obile/Li/com.saurik.te/vs/Cydia.app" ascii //weight: 1
        $x_1_4 = "ipwnder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


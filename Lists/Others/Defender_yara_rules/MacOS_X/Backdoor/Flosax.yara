rule Backdoor_MacOS_X_Flosax_A_2147659382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flosax.A"
        threat_id = "2147659382"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flosax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.apple.mdworker_server" ascii //weight: 1
        $x_1_2 = "{_xpc_connection_s=}" ascii //weight: 1
        $x_1_3 = "readMemoryByXPCFromComponent:forAgent:withCommandType:" ascii //weight: 1
        $x_1_4 = "xpc_connection_send_message_with_reply_sync" ascii //weight: 1
        $x_1_5 = "mXpcCon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MacOS_X_Flosax_A_2147659382_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flosax.A"
        threat_id = "2147659382"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flosax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{_xpc_connection_s=}" ascii //weight: 1
        $x_1_2 = "Library/LaunchAgents/com.apple.mdworker.plist" ascii //weight: 1
        $x_1_3 = "/System/Library/Frameworks/Foundation.framework/XPCServices" ascii //weight: 1
        $x_1_4 = "createSLIPlistWithBackdoor" ascii //weight: 1
        $x_1_5 = "_dropOsaxBundle" ascii //weight: 1
        $x_1_6 = "placeCallToHook" ascii //weight: 1
        $x_1_7 = "SendMessageHook:cchText:inHTML:" ascii //weight: 1
        $x_1_8 = "RCSMAgentApplication" ascii //weight: 1
        $x_1_9 = "com.apple.mdworker_server" ascii //weight: 1
        $x_1_10 = "mAgentConfiguration" ascii //weight: 1
        $x_1_11 = "hookKeyboardAndMouse" ascii //weight: 1
        $x_1_12 = "isACrisisApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MacOS_X_Flosax_A_2147659391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flosax.A!kext"
        threat_id = "2147659391"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flosax"
        severity = "Critical"
        info = "kext: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appleOsax" ascii //weight: 1
        $x_1_2 = ".kext.mchook" ascii //weight: 1
        $x_1_3 = "appleHID" ascii //weight: 1
        $x_2_4 = "/tmp/43t9903zz" ascii //weight: 2
        $x_2_5 = {83 f9 4f 7f 36 48 8d 51 01 80 3c 08 e8 75 ee 8b 74 08 01 8d 74 31 05 80 3c 30 55 75 e0}  //weight: 2, accuracy: High
        $x_2_6 = {83 fa 50 7d 24 8d 42 01 80 3c 11 e8 75 f0 8b 74 11 01 01 d6 80 7c 31 05 55 75 e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule TrojanSpy_MSIL_Tzeebot_A_2147679031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Tzeebot.A"
        threat_id = "2147679031"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tzeebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Cleaver.Net" ascii //weight: 2
        $x_1_2 = "GetMachinIPList" ascii //weight: 1
        $x_1_3 = "EmailSendPeriod" ascii //weight: 1
        $x_1_4 = "CreateNewKeyLogFile" ascii //weight: 1
        $x_1_5 = "CheckAndSaveLogFile" ascii //weight: 1
        $x_1_6 = "UserActivityHook_OnActiveWindowChanged" ascii //weight: 1
        $x_1_7 = "KillThisAgent" ascii //weight: 1
        $x_1_8 = "SaveConfigAndReload" ascii //weight: 1
        $x_1_9 = "ProcessUpdateCommands" ascii //weight: 1
        $x_3_10 = {06 17 58 0a 40 00 07 7e ?? ?? 00 04 7e ?? ?? 00 04 [0-2] 6f ?? ?? 00 0a 6f ?? ?? 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 0b}  //weight: 3, accuracy: Low
        $x_10_11 = "TZB_Startup" ascii //weight: 10
        $x_10_12 = "TinyZBot" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


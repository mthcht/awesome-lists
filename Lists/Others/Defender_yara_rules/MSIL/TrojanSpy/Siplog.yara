rule TrojanSpy_MSIL_Siplog_A_2147710223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Siplog.A"
        threat_id = "2147710223"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Siplog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 4b 69 6c 6c 41 56 00}  //weight: 10, accuracy: High
        $x_2_2 = {00 46 75 63 6b 46 69 6c 65 4e 61 6d 65 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 42 6f 74 6b 69 6c 6c 65 72 00}  //weight: 2, accuracy: High
        $x_1_4 = {00 4b 65 79 4c 6f 67 00}  //weight: 1, accuracy: High
        $x_2_5 = "iSpy Keylogger" wide //weight: 2
        $x_2_6 = "invisiblesoft.net/iSpySoft" wide //weight: 2
        $x_1_7 = {00 43 4c 49 50 42 4f 41 52 44 5f 4d 4f 4e 49 54 4f 52 49 4e 47 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Siplog_B_2147718384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Siplog.B"
        threat_id = "2147718384"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Siplog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "iSpy Keylogger" ascii //weight: 6
        $x_4_2 = "SpyKeylogger" wide //weight: 4
        $x_2_3 = "SpyKeylogger" ascii //weight: 2
        $x_4_4 = "MeltFile" ascii //weight: 4
        $x_3_5 = "RunStandardBotKiller" ascii //weight: 3
        $x_3_6 = "DecryptCoreFTPPassword" ascii //weight: 3
        $x_3_7 = "BotkillStartup" ascii //weight: 3
        $x_2_8 = "ExternalStealers" ascii //weight: 2
        $x_2_9 = "FuckFileName" ascii //weight: 2
        $x_2_10 = "Botkiller" ascii //weight: 2
        $x_2_11 = "KeyboardLogger" ascii //weight: 2
        $x_2_12 = "ClipboardLogger" ascii //weight: 2
        $x_2_13 = "ScreenshotLogger" ascii //weight: 2
        $x_2_14 = "WebcamLogger" ascii //weight: 2
        $x_2_15 = "AntivirusKiller" ascii //weight: 2
        $x_2_16 = "PasswordStealer" ascii //weight: 2
        $x_2_17 = "ModifyTaskManager" ascii //weight: 2
        $x_1_18 = "RecovationCheckChainExcludeRoot" ascii //weight: 1
        $x_1_19 = {46 69 6c 65 5a 69 6c 6c 61 00 44 69 72 65 63 74 6f 72 79}  //weight: 1, accuracy: High
        $x_1_20 = {4d 69 6e 65 63 72 61 66 74 00 4c 61 73 74 4c 6f 67 69 6e}  //weight: 1, accuracy: High
        $x_1_21 = "LastLoginPassword" ascii //weight: 1
        $x_1_22 = "get_LastLoginFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}


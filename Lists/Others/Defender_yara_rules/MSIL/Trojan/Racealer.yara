rule Trojan_MSIL_Racealer_DA_2147779226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.DA!MTB"
        threat_id = "2147779226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$4365bee4-1b24-4b5f-815e-d5408dea8639" ascii //weight: 20
        $x_5_2 = "CreateInstance" ascii //weight: 5
        $x_5_3 = "Activator" ascii //weight: 5
        $x_1_4 = "OnScreenKeyboard.Properties.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Racealer_DB_2147779227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.DB!MTB"
        threat_id = "2147779227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$519712d6-3c83-4b33-92b5-37f06995e528" ascii //weight: 20
        $x_20_2 = "$AAC9D1F6-E722-467C-8DAC-634967DB27FE" ascii //weight: 20
        $x_5_3 = "CreateInstance" ascii //weight: 5
        $x_5_4 = "Activator" ascii //weight: 5
        $x_1_5 = "SB.My.Resources" ascii //weight: 1
        $x_1_6 = "FallbackManager.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_11 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_12 = "DebuggableAttribute" ascii //weight: 1
        $x_1_13 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Racealer_DC_2147779337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.DC!MTB"
        threat_id = "2147779337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$911ecdbb-6ffa-4ada-98b0-057b35c96c74" ascii //weight: 20
        $x_20_2 = "$ac8362f3-12d1-4494-8035-51e0bc1c0104" ascii //weight: 20
        $x_20_3 = "$7ca129a6-a579-45c9-98d5-ab8d7e3b9e2d" ascii //weight: 20
        $x_20_4 = "$aeb71a23-736a-4721-93b9-c780e588a5a6" ascii //weight: 20
        $x_5_5 = "CreateInstance" ascii //weight: 5
        $x_5_6 = "Activator" ascii //weight: 5
        $x_1_7 = "IT_Helpdesk.My.Resources" ascii //weight: 1
        $x_1_8 = "Westland.My.Resources" ascii //weight: 1
        $x_1_9 = "Operating_System.Resources.resources" ascii //weight: 1
        $x_1_10 = "ForkJoin.Resources" ascii //weight: 1
        $x_1_11 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_12 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_13 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_14 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_15 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_16 = "DebuggableAttribute" ascii //weight: 1
        $x_1_17 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Racealer_DD_2147779973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.DD!MTB"
        threat_id = "2147779973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$64134bb9-16af-4982-81f1-416db085cd8c" ascii //weight: 20
        $x_20_2 = "$58c3caac-dd31-440d-bca4-75af26ef9342" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "openBlackbreeze.Resources.resources" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "kulerIslands.Properties.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_10 = "Activator" ascii //weight: 1
        $x_1_11 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_12 = "DebuggableAttribute" ascii //weight: 1
        $x_1_13 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Racealer_DE_2147780582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.DE!MTB"
        threat_id = "2147780582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FujiFuscator" ascii //weight: 1
        $x_1_2 = "IsLogging" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "get_IsAlive" ascii //weight: 1
        $x_1_5 = "GetHINSTANCE" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "AppDomain" ascii //weight: 1
        $x_1_8 = "set_IsBackground" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "Debugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racealer_DF_2147780810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.DF!MTB"
        threat_id = "2147780810"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crypted.exe" ascii //weight: 1
        $x_1_2 = "ConfuserEx" ascii //weight: 1
        $x_1_3 = "IsLogging" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "get_IsAlive" ascii //weight: 1
        $x_1_6 = "GetHINSTANCE" ascii //weight: 1
        $x_1_7 = "get_CurrentDomain" ascii //weight: 1
        $x_1_8 = "AppDomain" ascii //weight: 1
        $x_1_9 = "set_IsBackground" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "Debugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racealer_2147783162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.MT!MTB"
        threat_id = "2147783162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 0b 06 6f [0-4] 28 [0-4] 2a 32 00 02 28 [0-4] 73 [0-4] 0a 28 [0-4] 14 fe [0-5] 73 [0-4] 6f [0-4] 06 6f [0-4] 7e [0-4] 28}  //weight: 1, accuracy: Low
        $x_1_2 = "_PexesoGo" ascii //weight: 1
        $x_1_3 = "_PexesoWait" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racealer_BM_2147795784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.BM!MTB"
        threat_id = "2147795784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0c 08 08 1f 3c 58 4b e0 58 25 1c 58 49 0d 25 1f 14 58 49 13 04 16 e0 13 05 16 13 06 1f 18 58 11 04 58 13 07}  //weight: 10, accuracy: High
        $x_3_2 = "JixosdjI2" ascii //weight: 3
        $x_3_3 = "5OUTPUT-ONLINEPNGTOOLS" ascii //weight: 3
        $x_3_4 = "DownloadData" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racealer_BS_2147795785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.BS!MTB"
        threat_id = "2147795785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 08 1f 3c 58 4b e0 58 25 1c 58 49 0d 25 1f 14 58 49 13 04 16 e0 13 05 16 13 06 1f 18 58 11 04 58 13 07}  //weight: 10, accuracy: High
        $x_3_2 = "udfiasdkk" ascii //weight: 3
        $x_3_3 = "1OUTPUT-ONLINEPNGTOOLS" ascii //weight: 3
        $x_3_4 = "FromBase64String" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racealer_MA_2147809311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.MA!MTB"
        threat_id = "2147809311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 7e ?? ?? ?? 04 11 07 09 08 28 ?? ?? ?? 06 17 73 ?? ?? ?? 0a 13 05 7e ?? ?? ?? 04 11 05 11 06 16 11 06 8e 69 28 ?? ?? ?? 06 7e ?? ?? ?? 04 11 05 28 ?? ?? ?? 06 7e ?? ?? ?? 04 28 ?? ?? ?? 06 13 08 7e ?? ?? ?? 04 11 08 7e ?? ?? ?? 04 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 0a de}  //weight: 1, accuracy: Low
        $x_1_2 = "w3wp" wide //weight: 1
        $x_1_3 = "base64Binary" ascii //weight: 1
        $x_1_4 = "http://www.smartassembly.com" ascii //weight: 1
        $x_1_5 = "GetServerURL" ascii //weight: 1
        $x_1_6 = "GetWebRequest" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "WebProxy" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "RijndaelManaged" ascii //weight: 1
        $x_1_11 = "CreateDecryptor" ascii //weight: 1
        $x_1_12 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racealer_AAOB_2147889510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racealer.AAOB!MTB"
        threat_id = "2147889510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 20 a0 16 00 00 28 ?? 00 00 06 58 0a 06 20 a4 16 00 00 28 ?? 00 00 06 5d 0a 08 11 06 06 94 58 0c 08 20 a8 16 00 00 28 ?? 00 00 06 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 ac 16 00 00 28 ?? 00 00 06 5d 94 0d 11 07 07 02 07 91 09 61 d2 9c 07 20 b0 16 00 00 28 ?? 00 00 06 58 0b 07 02 28 ?? 00 00 06 25 26 69 32 83}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


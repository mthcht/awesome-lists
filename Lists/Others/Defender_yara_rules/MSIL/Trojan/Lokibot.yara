rule Trojan_MSIL_Lokibot_AL_2147766557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AL!MTB"
        threat_id = "2147766557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 16 02 7b ?? 00 00 04 a2 09 17 02 7b ?? 00 00 04 a2 09 18 72 ?? 72 02 70 a2 11 04 6f ?? 00 00 0a 1a 9a 13 05 11 05 09 13 06 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = "GiaoDien" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AL_2147766557_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AL!MTB"
        threat_id = "2147766557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 20 00 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 00 09 18 58 0d 00 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d d1}  //weight: 2, accuracy: Low
        $x_1_2 = "Interferometry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_SS_2147770169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.SS!MTB"
        threat_id = "2147770169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pnnxekouten5n025up3x" wide //weight: 1
        $x_1_2 = "l6bh3okf117ustby1ewy" wide //weight: 1
        $x_1_3 = "We4a3a3hmp2oei7wonjd6" wide //weight: 1
        $x_1_4 = "Xfl7sc2bybtrm3vrbetta" wide //weight: 1
        $x_1_5 = "WIOSOSOSOW" wide //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "CreateEventW" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
        $x_1_9 = "GetCurrentProcess" ascii //weight: 1
        $x_1_10 = "TerminateProcess" ascii //weight: 1
        $x_1_11 = "DgFqNyZD2NcjS7p60JGMch18mc8g" ascii //weight: 1
        $x_1_12 = "GetStartupInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AMP_2147773178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AMP!MTB"
        threat_id = "2147773178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rn0.Resources.resources" ascii //weight: 1
        $x_1_2 = "d5bb2d52ac22.Resources.resources" ascii //weight: 1
        $x_1_3 = "e4Z.Resources.resources" ascii //weight: 1
        $x_1_4 = "HelpKeywordAttribute" ascii //weight: 1
        $x_1_5 = "GeneratedCodeAttribute" ascii //weight: 1
        $x_1_6 = "EditorBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "CompareString" ascii //weight: 1
        $x_1_8 = "ToString" ascii //weight: 1
        $x_1_9 = "AsyncCallback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AMP_2147773178_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AMP!MTB"
        threat_id = "2147773178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AdminApp.AdminLogin.resources" ascii //weight: 1
        $x_1_2 = "AdminApp.AdminPanel.resources" ascii //weight: 1
        $x_1_3 = "AdminApp.MoveOutForm.resources" ascii //weight: 1
        $x_1_4 = "AdminApp.Previlege.resources" ascii //weight: 1
        $x_1_5 = "AdminApp.Properties.Resources.resources" ascii //weight: 1
        $x_1_6 = "AdminApp.ReceiptForm.resources" ascii //weight: 1
        $x_1_7 = "AdminApp.RegRecForm.resources" ascii //weight: 1
        $x_1_8 = "AdminApp.RoomForm.resources" ascii //weight: 1
        $x_1_9 = "AdminApp\\bin\\Debug" wide //weight: 1
        $x_1_10 = "hotel.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_MSIL_Lokibot_AMP_2147773178_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AMP!MTB"
        threat_id = "2147773178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HTG_Snake.A.resources" ascii //weight: 1
        $x_1_2 = "HTG_Snake.B.resources" ascii //weight: 1
        $x_1_3 = "HTG_Snake.C.resources" ascii //weight: 1
        $x_1_4 = "HTG_Snake.frmChoosePN.resources" ascii //weight: 1
        $x_1_5 = "HTG_Snake.frmBuyACard.resources" ascii //weight: 1
        $x_1_6 = "HTG_Snake.frmBigCard.resources" ascii //weight: 1
        $x_1_7 = "HTG_Snake.frmSnake.resources" ascii //weight: 1
        $x_1_8 = "HTG_Snake.frmFortune.resources" ascii //weight: 1
        $x_1_9 = "HTG_Snake.base.resources" ascii //weight: 1
        $x_1_10 = "HTG_Snake.frmFate.resources" ascii //weight: 1
        $x_1_11 = "HTG_Snake.Hi.resources" ascii //weight: 1
        $x_1_12 = "HTG_Snake.usai.resources" ascii //weight: 1
        $x_1_13 = "HTG_Snake.Main.resources" ascii //weight: 1
        $x_1_14 = "HTG_Snake.frmChooseAvatar.resources" ascii //weight: 1
        $x_1_15 = "HTG_Snake.frmWinner.resources" ascii //weight: 1
        $x_1_16 = "HTG_Snake.Deformatter.resources" ascii //weight: 1
        $x_1_17 = "HTG_Snake.HiSkor.resources" ascii //weight: 1
        $x_1_18 = "HTG_Snake.Resources.resources" ascii //weight: 1
        $x_1_19 = "$1956e73d-7392-424a-a755-3aa7b8738d47" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_RW_2147778600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.RW!MTB"
        threat_id = "2147778600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$d7dc3b91-b6b6-4b30-9c50-0fdd780f8f3c" ascii //weight: 1
        $x_1_2 = "remove_MouseClick" ascii //weight: 1
        $x_1_3 = "add_MouseClick" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "OutputDebugString" ascii //weight: 1
        $x_1_6 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_7 = "password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_RWA_2147778601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.RWA!MTB"
        threat_id = "2147778601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$d265be82-bc68-4e6e-abe9-e832886265db" ascii //weight: 1
        $x_1_2 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_4 = "get_Desktop" ascii //weight: 1
        $x_1_5 = "get_KeyChar" ascii //weight: 1
        $x_1_6 = "get_ResourceManager" ascii //weight: 1
        $x_1_7 = "KeyPressEventHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MFP_2147781043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MFP!MTB"
        threat_id = "2147781043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "$02f52f22-bdb2-4d2c-88b3-4194c27d33c3" ascii //weight: 1
        $x_1_3 = "XpSimulateParanoid" ascii //weight: 1
        $x_1_4 = "C:\\myapp.exe" ascii //weight: 1
        $x_1_5 = "RPF:SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MFP_2147781043_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MFP!MTB"
        threat_id = "2147781043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$d3866791-873f-4dc4-a695-9a3b7ed15bb1" ascii //weight: 1
        $x_1_2 = {57 1f a2 0b 09 1f 00 00 00 fa 01 33 00 16 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "SuspendLayout" ascii //weight: 1
        $x_1_4 = "LoadFile" ascii //weight: 1
        $x_1_5 = "get_Key" ascii //weight: 1
        $x_1_6 = "Hashtable" ascii //weight: 1
        $x_1_7 = "Clipboard" ascii //weight: 1
        $x_1_8 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "ContainsKey" ascii //weight: 1
        $x_1_11 = "ReadByte" ascii //weight: 1
        $x_1_12 = "KeyValuePair" ascii //weight: 1
        $x_1_13 = "Encoding" ascii //weight: 1
        $x_1_14 = "LateGet" ascii //weight: 1
        $x_1_15 = "set_ShortcutKeys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_PY_2147787473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.PY!MTB"
        threat_id = "2147787473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 02 14 72 ?? ?? ?? 70 14 14 14 28 ?? ?? ?? 0a a5 ?? ?? ?? 01 0b 02 07 17 59 91 1f ?? 61 0c 07 17 58 8d ?? ?? ?? 01 0d 16 13 ?? 16 13 ?? 2b ?? 00 09 11 ?? 02 11 ?? 91 08 61 06 11 ?? 91 61 d2 9c 11 ?? 03 6f ?? ?? ?? 0a 17 59 fe ?? 16 fe ?? 13 ?? 11 ?? 2c ?? 00 11 ?? 17 58 13 ?? 00 2b ?? 00 16 13 ?? 00 00 11 ?? 17 58 13 ?? 11 ?? 07 17 59 fe ?? 16 fe ?? 13 ?? 11 ?? 2d ?? 12 ?? 07 17 59 28 ?? ?? ?? 2b 00 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABXY_2147787474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABXY!MTB"
        threat_id = "2147787474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "iY5fyE6fsU3Hi" ascii //weight: 6
        $x_6_2 = "VYa_cBfkh/pur" ascii //weight: 6
        $x_1_3 = "$53d04ea0-0baa-4b63-b1a0-ab32d38967a2" ascii //weight: 1
        $x_1_4 = "GetHashCode" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "SuspendLayout" ascii //weight: 1
        $x_1_7 = "StreamReader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 5 of ($x_1_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_SST4_2147793668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.SST4!MTB"
        threat_id = "2147793668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 5a 20 da c6 74 89 61 2b ?? 07 6f ?? ?? ?? 0a 0a 11 ?? 20 ?? ?? ?? 43 5a 20 ?? ?? ?? 76 61 2b ?? 07 02 09 18 6f ?? ?? ?? 0a 1f ?? 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 20 ?? ?? ?? 9f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_SST1_2147793774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.SST1!MTB"
        threat_id = "2147793774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadFile" ascii //weight: 1
        $x_1_2 = "powershell Start-Process -FilePath" ascii //weight: 1
        $x_1_3 = "%Temp%" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Convert" ascii //weight: 1
        $x_1_6 = "/c powershell" ascii //weight: 1
        $x_1_7 = "ec632fd9-1694-4f4a-9bff-f20600e37981" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_SST2_2147793775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.SST2!MTB"
        threat_id = "2147793775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadData" ascii //weight: 1
        $x_1_2 = "Zula_HACK.exe" ascii //weight: 1
        $x_1_3 = "RunPE.dll" ascii //weight: 1
        $x_1_4 = "RunPE-Method-Bypass-AMSI-main" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
        $x_1_6 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DD_2147793983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DD!MTB"
        threat_id = "2147793983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D22222222222222" ascii //weight: 1
        $x_1_2 = {00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 00}  //weight: 1, accuracy: High
        $x_1_3 = "X234524324" ascii //weight: 1
        $x_1_4 = "gnirtS46esaBmorF" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
        $x_1_8 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DE_2147794056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DE!MTB"
        threat_id = "2147794056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_X_X0FT_FT1" ascii //weight: 1
        $x_1_2 = "_X_X0FT_FT2" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
        $x_1_8 = "getMyIP" ascii //weight: 1
        $x_1_9 = "_X_TSS3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_MSIL_Lokibot_DC_2147795108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DC!MTB"
        threat_id = "2147795108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {25 16 03 a2 14 14 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 0c 08 14 02 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 17 8d ?? ?? ?? 01 25 16 02 72 ?? ?? ?? 70 28 ?? ?? ?? 06 a2 14 14}  //weight: 20, accuracy: Low
        $x_1_2 = "ISectionEntry" ascii //weight: 1
        $x_1_3 = "StrReversex" ascii //weight: 1
        $x_1_4 = "epyTteG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DF_2147795883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DF!MTB"
        threat_id = "2147795883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c55cb53f-0d41-4629-8da8-207c4a33ef0a" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DJ_2147796737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DJ!MTB"
        threat_id = "2147796737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KOOOOOOOOOOOOOOO" ascii //weight: 1
        $x_1_2 = "RATCrypt\\LOKI\\" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DI_2147797345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DI!MTB"
        threat_id = "2147797345"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$72986061-9cdf-4601-af6f-0e92aff9f812" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DL_2147797766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DL!MTB"
        threat_id = "2147797766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShallowThought.GameEngine.resources" ascii //weight: 1
        $x_1_2 = "ShallowThought.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "CA.Gfx.Palette" ascii //weight: 1
        $x_1_4 = "CA.Engine" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DM_2147797767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DM!MTB"
        threat_id = "2147797767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$b6fb167d-4cb0-4eac-9ef3-83a2acf99be2" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DN_2147797768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DN!MTB"
        threat_id = "2147797768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 2b 32 7e ?? ?? ?? 04 7e ?? ?? ?? 04 06 7e ?? ?? ?? 04 06 8e 69 5d 91 9e 7e ?? ?? ?? 04 7e ?? ?? ?? 04 7e ?? ?? ?? 04 9e 7e ?? ?? ?? 04 17 58 80 ?? ?? ?? 04 7e ?? ?? ?? 04 20 00 01 00 00 32 c2 28 ?? ?? ?? 06 0f 00 28 ?? ?? ?? 06 7e ?? ?? ?? 04 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Crypto" ascii //weight: 1
        $x_1_3 = "cipher" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DP_2147797970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DP!MTB"
        threat_id = "2147797970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//45.133.1.84/gatty/mupdate.png" ascii //weight: 1
        $x_1_2 = "Gwrxydkukfgb" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "Animal" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DO_2147798233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DO!MTB"
        threat_id = "2147798233"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$4d4bce83-52d4-4b59-8465-10b8903348cb" ascii //weight: 20
        $x_20_2 = "$9484a5b9-8512-443d-b29b-72f4d12ebc77" ascii //weight: 20
        $x_20_3 = "$9331f6e0-e9c9-47b5-a75c-746c587b0ff8" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DQ_2147798236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DQ!MTB"
        threat_id = "2147798236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$8333121a-7b3e-4b23-ad75-5f53226aed83" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DR_2147798237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DR!MTB"
        threat_id = "2147798237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$8ce73e4f-6854-4895-85f7-72efc2df04cf" ascii //weight: 20
        $x_20_2 = "$a18950d3-335f-483f-881a-10a3c571e6ad" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DS_2147799394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DS!MTB"
        threat_id = "2147799394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d0d5af67-f90f-4d73-8ee0-9d7ef56220f7" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DT_2147799398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DT!MTB"
        threat_id = "2147799398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FormComponents.Properties.Resources" ascii //weight: 1
        $x_1_2 = "FormComponents.Form1.resources" ascii //weight: 1
        $x_1_3 = "PhotoResizer" ascii //weight: 1
        $x_1_4 = "Virtual Keyboard" ascii //weight: 1
        $x_1_5 = "Virtual Numpad" ascii //weight: 1
        $x_1_6 = "virtualKey" ascii //weight: 1
        $x_1_7 = "DebuggingModes" ascii //weight: 1
        $x_1_8 = "Bitmap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DU_2147805521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DU!MTB"
        threat_id = "2147805521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$a7a8527c-37ae-443b-8daa-61001cbd2658" ascii //weight: 20
        $x_20_2 = "$aef71a3a-c8f8-4d27-8ffd-20d0a49eace6" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DV_2147805522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DV!MTB"
        threat_id = "2147805522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d037e6cb-b822-4014-a48d-c672cc1d5301" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_NJKL_2147805596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.NJKL!MTB"
        threat_id = "2147805596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MICROSOFTEDPPERMISSIVEAPPINFO" ascii //weight: 1
        $x_1_2 = "GOOGLEUPDATEAPPLICATIONCOMMANDS" ascii //weight: 1
        $x_1_3 = "198 Protector V2" ascii //weight: 1
        $x_1_4 = "Select * from Win32_ComputerSystem" ascii //weight: 1
        $x_1_5 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_6 = "BlockCopy" ascii //weight: 1
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_9 = "Decrypt" ascii //weight: 1
        $x_1_10 = "cipherText" ascii //weight: 1
        $x_1_11 = "IAsyncResult" ascii //weight: 1
        $x_1_12 = "GetCurrentProcess" ascii //weight: 1
        $x_1_13 = "LoaderFlags" ascii //weight: 1
        $x_1_14 = "dotNetProtector" ascii //weight: 1
        $x_1_15 = "CreateDecryptor" ascii //weight: 1
        $x_1_16 = "Debugger" ascii //weight: 1
        $x_1_17 = "AssemblyBuilder" ascii //weight: 1
        $x_1_18 = "CryptoStream" ascii //weight: 1
        $x_1_19 = "IsLogging" ascii //weight: 1
        $x_1_20 = "FromBase64String" ascii //weight: 1
        $x_1_21 = "ObfuscatedByGoliath" ascii //weight: 1
        $x_1_22 = "set_UseShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DX_2147806261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DX!MTB"
        threat_id = "2147806261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d2cbf7f3-5480-4915-b6eb-d9fcae2f8f47" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DY_2147806264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DY!MTB"
        threat_id = "2147806264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d55fc6e2-d95a-4f76-91ec-cb884ee80958" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_DZ_2147807321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DZ!MTB"
        threat_id = "2147807321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$ec1698fe-5ea7-43ef-aea9-bfe0b0535c79" ascii //weight: 20
        $x_20_2 = "$a558aac3-7940-49c2-b364-7d967e2419b5" ascii //weight: 20
        $x_20_3 = "$da43fe0d-b4a1-4f48-ad15-1b9ee3fabf94" ascii //weight: 20
        $x_20_4 = "$5ee49b32-5c53-4d76-81e3-bb2f60db6ccc" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "FromBase64String" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EA_2147807583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EA!MTB"
        threat_id = "2147807583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Test-NetConnection -TraceRoute google.com" ascii //weight: 1
        $x_1_2 = "powershell" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "//cdn.discordapp.com/attachments/" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_EB_2147807584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EB!MTB"
        threat_id = "2147807584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$5ee49b32-5c53-4d76-81e3-bb2f60db6ccc" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EC_2147808442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EC!MTB"
        threat_id = "2147808442"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GuessMelody.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_3 = "OIHJBRSIGJOIGJG" ascii //weight: 1
        $x_1_4 = "IYUQWWQERWqrw" ascii //weight: 1
        $x_1_5 = "IUYWEW" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ED_2147809082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ED!MTB"
        threat_id = "2147809082"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$3263583a-3e96-4cce-8c9b-e7a9a38adfa0" ascii //weight: 20
        $x_20_2 = "$6aec1875-7803-4a31-be22-996e8db463d6" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EE_2147811444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EE!MTB"
        threat_id = "2147811444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$1fa58ed7-fa4b-4f32-af28-292fc36a3e15" ascii //weight: 20
        $x_20_2 = "$f542db96-68d2-437c-a3b2-00bbcece85ae" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EG_2147811445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EG!MTB"
        threat_id = "2147811445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$af6ea72d-b407-41ed-82d4-a3d2bd5e6b48" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EI_2147811455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EI!MTB"
        threat_id = "2147811455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q3J5cHRlZCBmZiQ=" ascii //weight: 1
        $x_1_2 = "Crypted ff" ascii //weight: 1
        $x_1_3 = "_Encrypted$" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "AppDomain" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
        $x_1_8 = "Convert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_EH_2147811586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EH!MTB"
        threat_id = "2147811586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$2a11704d-667a-4f22-939f-b8309290c5f2" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EJ_2147812190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EJ!MTB"
        threat_id = "2147812190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//cdn.discordapp.com/attachments/" ascii //weight: 1
        $x_1_2 = "EegrDowEegrnlEegroadDEegrataEegr" ascii //weight: 1
        $x_1_3 = "powershell" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "WindowsFormsApp" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "Bulk Email Software" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_EK_2147813043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EK!MTB"
        threat_id = "2147813043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bwnvqrl.dll" ascii //weight: 1
        $x_1_2 = "Vccspqmofucel" ascii //weight: 1
        $x_1_3 = "Ixsnbotsf" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GZipStream" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "Convert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_EL_2147813320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EL!MTB"
        threat_id = "2147813320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$1c2e5f9e-958b-4b36-80b3-c79d9d2a9657" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EM_2147813322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EM!MTB"
        threat_id = "2147813322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Twmfdc.Properties.Resources" ascii //weight: 1
        $x_1_2 = "//cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_3 = "/c ping yahoo.com" ascii //weight: 1
        $x_1_4 = "Yvdrzssskxtakpmlfn" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_EN_2147813386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EN!MTB"
        threat_id = "2147813386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d2d9ce8e-9f8c-4cde-b525-226b664d9434" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EO_2147815293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EO!MTB"
        threat_id = "2147815293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$b0d7724d-d988-4462-91de-13696bbec297" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_EP_2147815517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.EP!MTB"
        threat_id = "2147815517"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 04 20 ?? ?? ?? ?? 5d 07 11 04 20 ?? ?? ?? ?? 5d 91 08 11 04 1f 16 5d 6f ?? ?? ?? ?? 61 07 11 04 17 58 20 ?? ?? ?? ?? 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_IRFA_2147826270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.IRFA!MTB"
        threat_id = "2147826270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 05 00 00 04 73 3c 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 01 00 00 1b 0a 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 0b 07 72 ?? ?? ?? 70 28 ?? ?? ?? 06 74 3b 00 00 01 6f ?? ?? ?? 0a 1a 9a 80 04 00 00 04 23 d1 37 b7 3b 43 62 20 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_CZFA_2147828668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.CZFA!MTB"
        threat_id = "2147828668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 07 1f 16 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "ComputeHash" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_WJYF_2147828797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.WJYF!MTB"
        threat_id = "2147828797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 24 00 06 07 72 ?? ?? ?? 70 07 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 5d 28 ?? ?? ?? 0a 06 07 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_PAGA_2147829049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.PAGA!MTB"
        threat_id = "2147829049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06}  //weight: 2, accuracy: Low
        $x_1_2 = "N54VHQH78G" wide //weight: 1
        $x_1_3 = "Bambi" wide //weight: 1
        $x_1_4 = "ComputeHash" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MOYF_2147829233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MOYF!MTB"
        threat_id = "2147829233"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 0c 16 13 04 2b 21 00 07 11 04 08 11 04 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 07 11 04 91 61 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_OCGA_2147829663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.OCGA!MTB"
        threat_id = "2147829663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 07 28 ?? ?? ?? 0a 72 af 1c 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 73 c0 00 00 0a 0d 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "Heia" wide //weight: 1
        $x_1_3 = "Z754SHP5AU85A45IGZO44H" wide //weight: 1
        $x_1_4 = "TwoLevelEnumerator.Tucson" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_RPR_2147831929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.RPR!MTB"
        threat_id = "2147831929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 20 00 20 01 00 fe 04 13 05 11 05 2d a9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_RPR_2147831929_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.RPR!MTB"
        threat_id = "2147831929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 25 2b 49 2b ec 2b 48 2b ee 2b 47 2b ef 2b 46 2b 47 2b 48 06 8e 69 5d 91 02 08 91 61 d2 ?? ?? ?? ?? ?? 08 17 58 0c 08 02 8e 69 32 e1}  //weight: 1, accuracy: Low
        $x_1_2 = "descatalogandw.tk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABX_2147833104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABX!MTB"
        threat_id = "2147833104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 31 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 20 ?? ?? ?? 00 fe 04 13 05 11 05 2d a9 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Whale" wide //weight: 1
        $x_1_4 = "GameNetwork.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ALK_2147833950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ALK!MTB"
        threat_id = "2147833950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "16.6.936.3669" wide //weight: 1
        $x_1_2 = "Microsoft.WebTools.Shared.CPS.VS.dll" wide //weight: 1
        $x_1_3 = "16.6.936-preview3+550e59c1ad" wide //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AGJD_2147834053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AGJD!MTB"
        threat_id = "2147834053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d ca 06 03 07 8f}  //weight: 2, accuracy: High
        $x_1_2 = "Microsoft.Terminal.Wpf.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_RPP_2147834933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.RPP!MTB"
        threat_id = "2147834933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 59 20 00 01 00 00 6a 58 20 00 01 00 00 6a 5d d2 9c 00 07 15 58 0b 07 6c 23 00 00 00 00 00 00 00 00 23 00 00 00 00 00 00 00 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABDE_2147835713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABDE!MTB"
        threat_id = "2147835713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d6 13 07 11 07 04 5f 13 08 03 11 06 03 8e 69 14 14 17 28 ?? ?? ?? 06 91 13 09 08 11 06 16 16 02 17 8d ?? ?? ?? 01 25 16 11 06 8c ?? ?? ?? 01 a2 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 16 11 09 8c ?? ?? ?? 01 11 08 8c ?? ?? ?? 01 18 28 ?? ?? ?? 06 8c ?? ?? ?? 01 18 28 ?? ?? ?? 06 b4 9c}  //weight: 2, accuracy: Low
        $x_1_2 = "WindowsApp1.Resources" wide //weight: 1
        $x_1_3 = "njhuh77676" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MBDE_2147844580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MBDE!MTB"
        threat_id = "2147844580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 d5 01 00 00 06 07 02 7b ?? 00 00 04 08 6f ?? 00 00 0a 6f ?? 00 00 06 28 ?? 00 00 06 5a 02 7b ?? 00 00 04 08 6f ?? 00 00 0a 6f ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_2 = "b4b82a2f-dc34-4aa9-b237-d3017ec8beee" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_PSIY_2147844776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.PSIY!MTB"
        threat_id = "2147844776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 20 c7 01 00 00 20 8d 01 00 00 28 13 00 00 2b 0d 16 13 0a 11 0a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 09 6f ?? ?? ?? 0a d4 8d 24 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 26 11 0b 20 cd 01 00 00 93 20 24 34 00 00 59 13 0a 2b b3 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 13 05 de 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABUU_2147846332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABUU!MTB"
        threat_id = "2147846332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {16 13 05 2b 18 09 11 05 07 11 05 91 08 11 05 08 8e 69 5d 91 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 e1}  //weight: 4, accuracy: High
        $x_1_2 = "BallGamesWindowsFormsApp.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABVF_2147846877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABVF!MTB"
        threat_id = "2147846877"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 28 ?? 00 00 0a 08 28 ?? 00 00 0a 6f ?? 00 00 0a 14 17 8d ?? 00 00 01 25 16 07 a2 6f ?? 00 00 0a 75 ?? 00 00 1b 08 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 2a}  //weight: 4, accuracy: Low
        $x_1_2 = {31 00 39 00 32 00 2e 00 32 00 33 00 36 00 2e 00 31 00 39 00 32 00 2e 00 36 00 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_PSOB_2147847448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.PSOB!MTB"
        threat_id = "2147847448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 72 e8 00 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 0b 73 ?? ?? ?? 0a 0c 16 0d 16 13 04 2b 31 16 13 04 2b 1e 07 09 11 04 6f ?? ?? ?? 0a 13 06 08 12 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_PSOL_2147847531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.PSOL!MTB"
        threat_id = "2147847531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {60 7e 01 00 00 04 02 25 17 58 10 00 91 1f 18 62 60 0c 28 1e 00 00 0a 7e 01 00 00 04 02 08 6f 1f 00 00 0a 28 20 00 00 0a a5 02 00 00 1b 0b 11 07 20 a6 d7 df e7 5a 20 fa cc 6e f4 61 38 5e fd ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABXL_2147847814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABXL!MTB"
        threat_id = "2147847814"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DataBasePracticalJob" wide //weight: 2
        $x_2_2 = {52 00 61 00 74 00 69 00 6f 00 4d 00 61 00 73 00 74 00 65 00 72 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABXX_2147848014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABXX!MTB"
        threat_id = "2147848014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d 09 13 04 2b 00 11 04 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABXV_2147848237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABXV!MTB"
        threat_id = "2147848237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 c1 02 00 70 28 ?? 00 00 06 74 ?? 00 00 1b 0c 08 28 ?? 00 00 06 00 07 08 6f ?? 00 00 0a 00 07 06 72 cd 02 00 70 28 ?? 00 00 06 74 ?? 00 00 1b 6f ?? 00 00 0a 00 07 06 72 d9 02 00 70 28 ?? 00 00 06 74 ?? 00 00 1b 6f ?? 00 00 0a 00 02 28 ?? 00 00 06 00 28 ?? 00 00 06 07 6f ?? 00 00 0a 28 ?? 00 00 06 0d 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MBEM_2147849185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MBEM!MTB"
        threat_id = "2147849185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 08 07 6f ?? 01 00 0a 13 13 16 0d 11 05 06 9a ?? ?? ?? ?? ?? 28 ?? 01 00 06 28 ?? 00 00 0a 13 0c 11 0c 2c 0a 12 13 28 ?? 01 00 0a 0d 2b 44 11 05 06 9a ?? ?? ?? ?? ?? 28 ?? 01 00 06 28 ?? 00 00 0a 13 0d 11 0d 2c 0a 12 13 28 ?? 01 00 0a 0d 2b 21 11 05 06 9a ?? ?? ?? ?? ?? 28 a4 01 00 06 28 ?? 00 00 0a 13 0e 11 0e 2c 08 12 13 28 ?? 01 00 0a 0d 11 06 09 6f ?? 01 00 0a 08 17 58 0c 08 11 08 fe 04 13 0f 11 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MBFW_2147850545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MBFW!MTB"
        threat_id = "2147850545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 2b 22 11 04 11 05 18 6f ?? 00 00 0a 13 09 11 06 11 05 18 5b 11 09 1f 10 28 ?? 00 00 0a 9c 11 05 18 58 13 05 11 05 11 04 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d cd}  //weight: 1, accuracy: Low
        $x_1_2 = "19ab409aed58" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AMAA_2147891393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AMAA!MTB"
        threat_id = "2147891393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 11 04 5d 13 06 06 11 07 5d 13 0b 07 11 06 91 13 0c 11 05 11 0b 6f ?? 00 00 0a 13 0d 07 06 17 58 11 04 5d 91 13 0e 11 0c 11 0d 11 0e 28 ?? 00 00 06 13 0f 07 11 06 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 10 11 10 2d ae}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_CCCD_2147892396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.CCCD!MTB"
        threat_id = "2147892396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 07 8e 69 5d 13 07 11 06 08 6f ?? ?? ?? ?? 5d 13 08 07 11 07 91 13 09 08 11 08 6f ?? ?? ?? ?? 13 0a 02 07 11 06 28 ?? ?? ?? ?? 13 0b 02 11 09 11 0a 11 0b 28 ?? ?? ?? ?? 13 0c 07 11 07 02 11 0c 28 ?? ?? ?? ?? 9c 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 0d 11 0d 2d a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MBJQ_2147892577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MBJQ!MTB"
        threat_id = "2147892577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$cc7fad03-816e-432c-9b92-001f2d358389" ascii //weight: 1
        $x_1_2 = "server.Resources.resource" ascii //weight: 1
        $x_1_3 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_4 = "Important sysym file" ascii //weight: 1
        $x_1_5 = "server1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MBEN_2147895689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MBEN!MTB"
        threat_id = "2147895689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 8e 69 5d 13 04 07 09 6f ?? 00 00 0a 5d 13 08 06 11 04 91 13 09 09 11 08 6f ?? 00 00 0a 13 0a 02 06 07 28 ?? 00 00 06 13 0b 02 11 09 11 0a 11 0b 28 ?? 00 00 06 13 0c 06 11 04 11 0c 20 00 01 00 00 5d d2 9c 07 17 59 0b 07 16 fe 04 16 fe 01 13 0d 11 0d 2d a9}  //weight: 1, accuracy: Low
        $x_1_2 = "JeopardyGame.Properties.Resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AAVZ_2147895741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AAVZ!MTB"
        threat_id = "2147895741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 18 5b 8d ?? 00 00 01 0b 16 0c 2b 19 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 08 18 58 0c 08 06 fe 04 0d 09 2d df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_PTDT_2147898625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.PTDT!MTB"
        threat_id = "2147898625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 af d0 c9 86 28 ?? 00 00 2b 28 ?? 00 00 06 28 ?? 00 00 06 0a 06 28 ?? 00 00 06 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_PTED_2147899089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.PTED!MTB"
        threat_id = "2147899089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f 16 58 0a 2b 43 06 09 5d 13 05 06 11 08 5d 13 0c 07 11 05 91 13 0d 11 04 11 0c 6f b3 00 00 0a 13 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_PSAP_2147899287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.PSAP!MTB"
        threat_id = "2147899287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1a 59 28 26 00 00 0a 11 07 20 52 79 e2 89 5a 20 1d 7b 68 9d 61 38 a9 fd ff ff 28 27 00 00 0a 7e 01 00 00 04 02 08 6f 28 00 00 0a 28 29 00 00 0a a5 01 00 00 1b 0b 11 07 20 05 2a c9 ad 5a 20 ca ef 63 1d 61 38 7a fd ff ff 11 07 20 2f e6 d3 14 5a 20 82 e7 a4 08 61 38 67 fd ff ff}  //weight: 5, accuracy: High
        $x_1_2 = "xzGxZa8" ascii //weight: 1
        $x_1_3 = "Am7D%&" ascii //weight: 1
        $x_1_4 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_5 = "DESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_DK_2147899395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.DK!MTB"
        threat_id = "2147899395"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 09 11 05 9e 11 07 11 07 07 94 11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 02 08 91 11 04 61 d2 9c 08 17 58 0c 08 02 8e 69 32 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_HTAA_2147905145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.HTAA!MTB"
        threat_id = "2147905145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 dd 00 00 00 00 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_SG_2147906258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.SG!MTB"
        threat_id = "2147906258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "$cc7fad03-816e-432c-9b92-001f2d358889" ascii //weight: 3
        $x_1_2 = "FailFast" ascii //weight: 1
        $x_1_3 = "VHD Image" ascii //weight: 1
        $x_3_4 = "$cc7fad03-816e-432c-9b92-001f2d358699" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_KAB_2147910916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.KAB!MTB"
        threat_id = "2147910916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 6e 08 8e 69 6a 5d d4 91 58 11 ?? 09 95 58 20 ff 00 00 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_KAA_2147910961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.KAA!MTB"
        threat_id = "2147910961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c}  //weight: 1, accuracy: High
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MA_2147911090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MA!MTB"
        threat_id = "2147911090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "server1.exe" ascii //weight: 1
        $x_1_2 = "Recovery Tool" ascii //weight: 1
        $x_1_3 = "FailFast" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_5_5 = "jnoit Yot" wide //weight: 5
        $x_5_6 = "Qot Recovery" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_CCIG_2147912060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.CCIG!MTB"
        threat_id = "2147912060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 0d d4 11 0e 6e 11 11 20 ?? ?? ?? ?? 5f 6a 61 d2 9c 11 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AMMI_2147912259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AMMI!MTB"
        threat_id = "2147912259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 07 06 91 11 ?? 61 13 ?? 07 06 17 58 07 8e 69 5d 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ASEK_2147912373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ASEK!MTB"
        threat_id = "2147912373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 1f 16 5d 91 13 ?? 07 09 91 11 ?? 61 09 17 58 07 8e 69 5d 13 ?? 07 11 ?? 91 13 ?? 11 ?? 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 ?? 07 09 11 ?? d2 9c 09 17 58 0d 09 07 8e 69 32}  //weight: 4, accuracy: Low
        $x_1_2 = "TY44BHE777W44GTU4FCAFA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AMAM_2147915596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AMAM!MTB"
        threat_id = "2147915596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 95 d2 13 [0-10] 61 [0-15] 20 ff 00 00 00 5f d2 9c 00 11 ?? 17 6a 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_RFAA_2147915636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.RFAA!MTB"
        threat_id = "2147915636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 07 28 ?? 00 00 06 13 07 1f 10 8d ?? 00 00 01 13 08 0e 04 13 09 11 09 39 19 00 00 00 00 08}  //weight: 2, accuracy: Low
        $x_3_2 = {0a 11 07 16 1f 10 6f ?? 00 00 0a 13 08 00 11 08 07 28 ?? 00 00 06 13 08 0e 04 16 fe 01 13 0a 11 0a 39 ?? 00 00 00 00 11 08 28 ?? 00 00 06 13 08 00 11 08 16 06 11 04 11 06 28 ?? 00 00 0a 00 07 28 ?? 00 00 06 0b 00 11 04 1f 10 58 13 04}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_RGAA_2147915712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.RGAA!MTB"
        threat_id = "2147915712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 11 0f d4 11 13 20 ff 00 00 00 5f d2 9c}  //weight: 2, accuracy: High
        $x_3_2 = {11 06 11 11 20 ff 00 00 00 5f 95 d2 13 12 11 10 11 12 61 13 13}  //weight: 3, accuracy: High
        $x_1_3 = "524OZ4CTQ7ZJ8GE7I7C8JA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_RUAA_2147916310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.RUAA!MTB"
        threat_id = "2147916310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 0b 11 0b 11 07 28 ?? 00 00 06 13 0c 73 ?? 00 00 06 13 0d 11 0d 72 ?? ?? 00 70 1d 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 25 17 72 ?? ?? 00 70 a2 25 18 11 0c a2 25 19 17 8c ?? 00 00 01 a2 25 1a 16 8c ?? 00 00 01 a2 25 1b}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MBXU_2147921637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MBXU!MTB"
        threat_id = "2147921637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "GiauTM.CSharp.TikiRouter" wide //weight: 4
        $x_3_2 = "Arvore" ascii //weight: 3
        $x_2_3 = "Split" ascii //weight: 2
        $x_1_4 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_XDAA_2147921698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.XDAA!MTB"
        threat_id = "2147921698"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 05 0e 04 6f ?? 00 00 0a 0a 03 6f ?? 00 00 0a 19 58 04 fe 02 16 fe 01 0b}  //weight: 3, accuracy: Low
        $x_2_2 = {02 0f 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 02 0f 01 28 ?? 00 00 0a 6f ?? 00 00 0a 16 0b 2b c6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AMC_2147921790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AMC!MTB"
        threat_id = "2147921790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 18 fe 04 16 fe 01 13 06 11 06 2c 0e 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 19 fe 01 13 07 11 07 2c 0e 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_GM_2147922101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.GM!MTB"
        threat_id = "2147922101"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {00 00 01 25 16 03 16 9a a2 25 17 03 17 9a a2 25 18 04 a2 0a}  //weight: 8, accuracy: High
        $x_1_2 = "sgtatham/putty/0" ascii //weight: 1
        $x_1_3 = "Trif32" ascii //weight: 1
        $x_1_4 = "190316123152Z0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lokibot_ZDAA_2147923213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ZDAA!MTB"
        threat_id = "2147923213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 06 07 6f ?? 00 00 0a 1d 62 06 07 17 58 6f ?? 00 00 0a 1c 62 58 06 07 18 58 6f ?? 00 00 0a 1b 62 58 06 07 19 58 6f ?? 00 00 0a 1a 62 58 06 07 1a 58 6f ?? 00 00 0a 19 62 58 06 07 1b 58 6f ?? 00 00 0a 18 62 58 06 07 1c 58 6f ?? 00 00 0a 17 62 58 06 07 1d 58 6f ?? 00 00 0a 58 d2 6f ?? 00 00 0a 07 1e 58 0b 07 06 6f ?? 00 00 0a fe 04 13 08 11 08 2d 8a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AMBA_2147924448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AMBA!MTB"
        threat_id = "2147924448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 13 0e 2b 17 11 0a 11 0e 11 09 11 0e 9a 1f 10 28 ?? 00 00 0a 9c 11 0e 17 d6 13 0e 11 0e 11 09 8e 69 fe 04 13 0f 11 0f 2d db}  //weight: 3, accuracy: Low
        $x_2_2 = {13 08 11 08 17 8d 77 00 00 01 25 16 1f 2d 9d 6f ?? 00 00 0a 13 09 11 09 8e 69 8d 5b 00 00 01 13 0a}  //weight: 2, accuracy: Low
        $x_1_3 = "EsmGj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ASEL_2147929484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ASEL!MTB"
        threat_id = "2147929484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 11 0a 11 09 6f ?? 01 00 0a 13 0b 12 0b 28 ?? 01 00 0a 20 ff 00 00 00 fe 01 16 fe 01 13 0c 11 0c 39 ?? 00 00 00 00 09 11 04 12 0b 28 ?? 01 00 0a 9c}  //weight: 4, accuracy: Low
        $x_1_2 = {11 04 17 58 13 04 00 11 0a 17 58 13 0a 11 0a 06 fe 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AGIA_2147929950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AGIA!MTB"
        threat_id = "2147929950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 06 20 ff 00 00 00 5f d2 9c 0b}  //weight: 4, accuracy: High
        $x_2_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AKMA_2147934519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AKMA!MTB"
        threat_id = "2147934519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {58 0a 06 19 5a 20 00 01 00 00 5d 0a 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 1f 55 61 d2 9c 25 17 0f 00 28 ?? 00 00 0a 20 aa 00 00 00 61 d2 9c 25 18 0f 00 28 ?? 00 00 0a 1f 33 61 d2 9c}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_MPV_2147937069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.MPV!MTB"
        threat_id = "2147937069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 05 02 20 00 03 00 00 20 32 03 00 00 28 ?? 00 00 2b 58 02 20 95 03 00 00 20 a7 03 00 00 28 ?? 00 00 2b 5d 06 02 20 30 01 00 00 20 03 01 00 00 28 ?? 00 00 2b 58 02 20 03 02 00 00 20 30 02 00 00 28 ?? 00 00 2b 5d 20 02 02 00 00 20 3a 02 00 00 28 a9 00 00 2b 04 03 6f ad 01 00 0a 59 0c 08 03 07 74 4a 00 00 1b 28 01 02 00 06 11 07 20 05 01 00 00 93 20 7a 25 00 00 59 13 05 38 c9 fe ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AKQA_2147938273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AKQA!MTB"
        threat_id = "2147938273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 05 11 07 6f ?? 00 00 0a 13 08 09 17 58 0d 05 13 0a 11 0a 39 ?? 00 00 00 00 11 04 13 0b 11 0b 72 da 26 00 70 11 0b 72 da 26 00 70 6f ?? 00 00 0a 12 08 28 ?? 00 00 0a 58 6f ?? 00 00 0a 00 11 04 13 0b 11 0b 72 e2 26 00 70 11 0b 72 e2 26 00 70 6f ?? 00 00 0a 12 08 28 ?? 00 00 0a 58 6f ?? 00 00 0a 00 11 04 13 0b 11 0b 72 ee 26 00 70 11 0b 72 ee 26 00 70 6f ?? 00 00 0a 12 08 28 ?? 00 00 0a 58}  //weight: 5, accuracy: Low
        $x_2_2 = {11 08 16 28 ?? 00 00 06 13 11 11 08 17 28 ?? 00 00 06 13 12 11 08 18 28 ?? 00 00 06 13 13 03 11 11 6f ?? 00 00 0a 00 03 11 12 6f ?? 00 00 0a 00 03 11 13 6f ?? 00 00 0a 00 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AWQA_2147938673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AWQA!MTB"
        threat_id = "2147938673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 11 05 07 11 05 94 02 5a 1f 64 5d 9e 00 11 05 17 58 13 05}  //weight: 3, accuracy: High
        $x_3_2 = {07 11 07 07 11 07 94 03 5a 1f 64 5d 9e}  //weight: 3, accuracy: High
        $x_2_3 = "Student_Housing.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_AURA_2147939840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.AURA!MTB"
        threat_id = "2147939840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0e 02 11 0b 11 0d 6f ?? 00 00 0a 7d ?? 00 00 04 11 0e 04 11 0e 7b ?? 00 00 04 7b ?? 00 00 04 6f ?? 00 00 0a 59 7d ?? 00 00 04 11 17}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c 25 17 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c 25 18 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
        $x_2_3 = "Assignment2_Winform.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lokibot_ABL_2147940691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokibot.ABL!MTB"
        threat_id = "2147940691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 0d 2b 25 11 0c 11 0d 94 13 0e 00 11 0e 16 fe 04 13 0f 11 0f 2c 0b 72 ?? 01 00 70 73 ?? 00 00 0a 7a 00 11 0d 17 58 13 0d 11 0d 11 0c 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


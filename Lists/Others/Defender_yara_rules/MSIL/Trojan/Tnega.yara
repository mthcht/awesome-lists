rule Trojan_MSIL_Tnega_RT_2147763138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.RT!MTB"
        threat_id = "2147763138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Runtime.InteropServices" ascii //weight: 1
        $x_1_2 = "System.Runtime.CompilerServices" ascii //weight: 1
        $x_1_3 = "System.Resources" ascii //weight: 1
        $x_1_4 = "CowsAndBulls.GameForm.resources" ascii //weight: 1
        $x_1_5 = "CowsAndBulls.HighScoresForm.resources" ascii //weight: 1
        $x_1_6 = "CowsAndBulls.MainMenuForm.resources" ascii //weight: 1
        $x_1_7 = "CowsAndBulls.Properties.Resources.resources" ascii //weight: 1
        $x_5_8 = "4C816952BA53CC361D8E45BD833338DC6427E4A5D5F06EBAD5351FD46439A15A" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_AQ_2147765653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.AQ!MTB"
        threat_id = "2147765653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "75FyxwPHwmKHAcw78F" ascii //weight: 1
        $x_1_2 = "set_TradeBanStateGetTypesFromInterfaceParseUInt16" ascii //weight: 1
        $x_1_3 = "HasPermissionsFixedUpdateadd_OnPluginLoading" ascii //weight: 1
        $x_1_4 = "HasPermissionsadd_OnPluginsLoadedAddPlayerToGroup" ascii //weight: 1
        $x_1_5 = "get_Clientsset_SteamID64get_DefaultTranslations" ascii //weight: 1
        $x_1_6 = "remove_OnPluginsLoadedParseDoubleget_Syntax" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_AL_2147768083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.AL!MTB"
        threat_id = "2147768083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TOKEN_STEALER_CREATOR.Properties" ascii //weight: 1
        $x_1_2 = "$340becfa-1688-4c32-aa49-30fdb4005e4b" ascii //weight: 1
        $x_1_3 = "ItroublveTSC\\bin_copy\\obj\\Debug" ascii //weight: 1
        $x_1_4 = "C:/temp/finalres.bat" wide //weight: 1
        $x_1_5 = "C:/temp/finalres2.vbs" wide //weight: 1
        $x_1_6 = "C:/temp/WebBrowserPassView.exe" wide //weight: 1
        $x_1_7 = "C:/temp/curl.exe" wide //weight: 1
        $x_1_8 = "C:/temp/filed.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_MS_2147770002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.MS!MTB"
        threat_id = "2147770002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ApplyRequest.dll" ascii //weight: 1
        $x_1_2 = "ScriptDDL" ascii //weight: 1
        $x_1_3 = "_lstStatusExec" ascii //weight: 1
        $x_1_4 = "_userPassword" ascii //weight: 1
        $x_1_5 = "_dsRequest" ascii //weight: 1
        $x_1_6 = "_reqScript" ascii //weight: 1
        $x_1_7 = "_frameServer" ascii //weight: 1
        $x_1_8 = "_requestServer" ascii //weight: 1
        $x_1_9 = "ExecuteAllSteps" ascii //weight: 1
        $x_1_10 = "add_SendStatusRequest" ascii //weight: 1
        $x_1_11 = "SendProgressExec" ascii //weight: 1
        $x_1_12 = "GerarScriptsDrop" ascii //weight: 1
        $x_1_13 = "GetListReplaceDll" ascii //weight: 1
        $x_1_14 = "VerificaForeignKeys" ascii //weight: 1
        $x_1_15 = "lblcomputadorresponsavel" ascii //weight: 1
        $x_1_16 = "txtUser_Validated" ascii //weight: 1
        $x_1_17 = "VerificaVersaoPlugin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Trojan_MSIL_Tnega_AMP_2147773165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.AMP!MTB"
        threat_id = "2147773165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xola.exe" wide //weight: 1
        $x_1_2 = "CLS.dll" wide //weight: 1
        $x_1_3 = "yhxGkJfDMpTfiUkihOywMGfEhwUUQLLMnQOsEBvpnBEZUkExQhTyUQhJwkMJAisikT" wide //weight: 1
        $x_1_4 = "SecurityPermissionAttribute" ascii //weight: 1
        $x_1_5 = "SHA256CryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "Encoding" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "hpCGGsxnBfkpZyTC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_AMP_2147773165_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.AMP!MTB"
        threat_id = "2147773165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TankGame.My.Resources" ascii //weight: 1
        $x_1_2 = "TankGame.Game.resources" ascii //weight: 1
        $x_1_3 = "TankGame.MainForm.resources" ascii //weight: 1
        $x_1_4 = "TankGame.StartUp.resources" ascii //weight: 1
        $x_1_5 = "TankGame.Resources.resources" ascii //weight: 1
        $x_1_6 = "TankGame.MultipleBlocks.resources" ascii //weight: 1
        $x_1_7 = "TankGame.InGameOptions.resources" ascii //weight: 1
        $x_1_8 = "TankGame.QuickStart.resources" ascii //weight: 1
        $x_1_9 = "$B587AAD2-1EA4-416F-9904-BD8D4AF3A072" ascii //weight: 1
        $x_1_10 = "FromBase64String" wide //weight: 1
        $x_1_11 = "Software\\VBSamples\\Collapse\\HighScores" wide //weight: 1
        $x_1_12 = "WinForms_RecursiveFormCreate" wide //weight: 1
        $x_1_13 = "WinForms_SeeInnerException" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_AM_2147781183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.AM!MTB"
        threat_id = "2147781183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crypter" ascii //weight: 1
        $x_1_2 = "linkxmr" ascii //weight: 1
        $x_1_3 = "set_ShowInTaskbar" ascii //weight: 1
        $x_1_4 = "RNGCryptoServiceProvider" ascii //weight: 1
        $x_1_5 = "Task24Main.pdb" ascii //weight: 1
        $x_1_6 = "mconhost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_MA_2147786445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.MA!MTB"
        threat_id = "2147786445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 11 04 06 11 04 91 07 11 04 07 8e 69 5d 91 09 58 20 ff 00 00 00 5f 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 17 59 fe 02 16 fe 01 13 05 11 05 2d ce}  //weight: 10, accuracy: High
        $x_3_2 = "SecurityProtocolType" ascii //weight: 3
        $x_3_3 = "HttpWebResponse" ascii //weight: 3
        $x_3_4 = "DebuggerBrowsableAttribute" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_UMQ_2147787404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.UMQ!MTB"
        threat_id = "2147787404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asdfasdasf" ascii //weight: 1
        $x_1_2 = "fdsfds" ascii //weight: 1
        $x_1_3 = "gsdfsfsd" ascii //weight: 1
        $x_1_4 = ".WEB_WEBSITE_BROWSER_PAGE_WIREFRAME_ICON_18934" wide //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "BitTreeDecoder" ascii //weight: 1
        $x_1_7 = "DecodeWithMatchByte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_HXS_2147787482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.HXS!MTB"
        threat_id = "2147787482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CellManager.g.resources" ascii //weight: 5
        $x_5_2 = "CellManager.exe" ascii //weight: 5
        $x_5_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 5
        $x_1_4 = "Google LLC" ascii //weight: 1
        $x_1_5 = "Discord Inc" ascii //weight: 1
        $x_5_6 = "11111-22222-10009-11112" ascii //weight: 5
        $x_5_7 = "11111-22222-50001-00002" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Tnega_HWJ_2147787669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.HWJ!MTB"
        threat_id = "2147787669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XRails.Controls" ascii //weight: 1
        $x_1_2 = "Slowloris" ascii //weight: 1
        $x_1_3 = "SlowlorisThread" ascii //weight: 1
        $x_1_4 = "TwiceSlicePanel.UI" ascii //weight: 1
        $x_1_5 = "CredentialManagement" ascii //weight: 1
        $x_1_6 = "get_UseSystemPasswordChar" ascii //weight: 1
        $x_1_7 = "DomainVisiblePassword" ascii //weight: 1
        $x_1_8 = "set_SecurePassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_DHI_2147788129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.DHI!MTB"
        threat_id = "2147788129"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows10UpdateAssistant.exe" wide //weight: 1
        $x_1_2 = "get_ActivatePo_ng" ascii //weight: 1
        $x_1_3 = "ReadServertData" ascii //weight: 1
        $x_1_4 = "PROCESSENTRY32" ascii //weight: 1
        $x_1_5 = "Client.Connection" ascii //weight: 1
        $x_1_6 = "VirusDeleted" ascii //weight: 1
        $x_1_7 = "DecodeFromStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_DFS_2147788916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.DFS!MTB"
        threat_id = "2147788916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gold.exe" wide //weight: 1
        $x_1_2 = "GoldMU#@123MU" wide //weight: 1
        $x_1_3 = "103.145.4.208" wide //weight: 1
        $x_1_4 = "UJi}QEfzNFfzNDcwPd" ascii //weight: 1
        $x_1_5 = "PacketFileManager_DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_IDI_2147788939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.IDI!MTB"
        threat_id = "2147788939"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0f 00 00 0a 25 72 01 00 00 70 6f 10 00 00 0a 26 25 72 75 00 00 70 6f 10 00 00 0a 26 25 72 d9 00 00 70 6f 10 00 00 0a 26 6f 11 00 00 0a 26 72}  //weight: 1, accuracy: High
        $x_1_2 = "AMR_DOWN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_B_2147788941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.B!MTB"
        threat_id = "2147788941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\EACInfo.txt" wide //weight: 1
        $x_1_2 = "EscapeFromTarkov_Data\\StreamingAssets\\Windows\\shaders" wide //weight: 1
        $x_1_3 = "GxP6yGPwtZJTjM5nLF1kquatccbmojv9ETK.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_ING_2147789079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.ING!MTB"
        threat_id = "2147789079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://91.241.19.52" wide //weight: 1
        $x_1_2 = "Runtimebroker.exe" wide //weight: 1
        $x_1_3 = "RawZipAndAes" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "ProcessStartInfo" ascii //weight: 1
        $x_1_6 = "get_StartupPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_YN_2147789209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.YN!MTB"
        threat_id = "2147789209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoWin.Properties.Resources" wide //weight: 1
        $x_1_2 = "AutoUpdaterDotNET.Properties.Resources" wide //weight: 1
        $x_1_3 = "MaterialSkin.Properties.Resources" wide //weight: 1
        $x_1_4 = "MetroFramework.Properties.Resources" wide //weight: 1
        $x_1_5 = "GetStringBalanceWallet" ascii //weight: 1
        $x_1_6 = "SendMoveBoUSDT" ascii //weight: 1
        $x_1_7 = "CheckBietDanh" ascii //weight: 1
        $x_1_8 = "DownloadChromeDriver" ascii //weight: 1
        $x_1_9 = "Chuyentien" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_PAG_2147789451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.PAG!MTB"
        threat_id = "2147789451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\7AAAAAAAAAAAAAA" ascii //weight: 2
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "p,o,we,rs,he,ll" ascii //weight: 1
        $x_1_4 = "Fro@mBa@se6@4St@ring@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_IFK_2147793174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.IFK!MTB"
        threat_id = "2147793174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ppphhyf.exe" ascii //weight: 1
        $x_1_2 = "cdscdscdsd.exe" wide //weight: 1
        $x_1_3 = "_ICON_1913" wide //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "BlockCopy" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "get_CurrentDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_INL_2147793939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.INL!MTB"
        threat_id = "2147793939"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments/873670006070738958/874223276182867989/csharp.dll" wide //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "Form1_Load" ascii //weight: 1
        $x_1_4 = "198-ProtectorA198-Protector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_IKV_2147794361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.IKV!MTB"
        threat_id = "2147794361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 02 08 00 00 28 12 00 00 0a 73 58 00 00 0a 0a 06 72 23 10 00 70 28 7b 00 00 06 6f 59 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = {20 d5 07 00 00 28 12 00 00 0a 02 04 28 55 00 00 06 03 17 18 8d 01 00 00 01 0a 06 28 5b 00 00 0a 26 2a}  //weight: 1, accuracy: High
        $x_1_3 = "tererererwgamal.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_PA_2147794824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.PA!MTB"
        threat_id = "2147794824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://80.66.75.25/" wide //weight: 1
        $x_1_2 = {19 2d 09 26 2b 21 0a 2b ea 0b 2b f3 0c 2b f5 07 08 18 5b 02 08 18 6f 26 00 00 0a 1f 10 28 27 00 00 0a 9c 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_BIF_2147798371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.BIF!MTB"
        threat_id = "2147798371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments/895494963515772931/895591057251762186/test_2.dll" ascii //weight: 1
        $x_1_2 = "Bentenform.Bentenform" wide //weight: 1
        $x_1_3 = "__StaticArrayInitTypeSize=87" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_M_2147799519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.M!MTB"
        threat_id = "2147799519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\OneDrive\\Projects\\OneDriveTimer\\OneDriveTimerUI\\obj\\Release\\OneDriveTimerUI.pdb" ascii //weight: 1
        $x_1_2 = "OneDriveTimerUI.Properties.Resources" ascii //weight: 1
        $x_1_3 = "OneDriveTimerUI.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_MD_2147808968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.MD!MTB"
        threat_id = "2147808968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|h|t|t|p|s|:|/|/|t|e|x|t|b|i|n|.|n|e|t|/|" wide //weight: 1
        $x_1_2 = "SELECT * FROM Credentials" wide //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "CenterToScreen" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "_txtPassword" ascii //weight: 1
        $x_1_7 = "Username:" wide //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_MB_2147809047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.MB!MTB"
        threat_id = "2147809047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 0d 09 11 0d 10 00 20 00 10 00 00 8d ?? 00 00 01 [0-6] 16 20 ?? ?? ?? 4f 20 ?? ?? ?? 0c 61 20 ?? ?? ?? 43 59 6f ?? ?? ?? 0a 13 0b 08 11 0d 16 11 0b 6f ?? ?? ?? 0a 09 11 0d 16 20 ?? ?? ?? 05 20 ?? ?? ?? 0e 61 20 ?? ?? ?? 0d 20 ?? ?? ?? 02 59 59 6f ?? ?? ?? 0a 13 0b 11 0b 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "ClipboardProxy" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "SetThreadExecutionState" ascii //weight: 1
        $x_1_7 = "RijndaelManaged" ascii //weight: 1
        $x_1_8 = "GZipStream" ascii //weight: 1
        $x_1_9 = "NetworkCredential" ascii //weight: 1
        $x_1_10 = "Write" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_BL_2147810206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.BL!MTB"
        threat_id = "2147810206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bwDownloader" ascii //weight: 1
        $x_1_2 = "$d3fa0898-ef22-449f-aa82-5f6b7fe63c42" ascii //weight: 1
        $x_1_3 = "obfuscatorBytes" ascii //weight: 1
        $x_1_4 = "Obfuscator" ascii //weight: 1
        $x_1_5 = "obfuscatorErrorLog.txt" wide //weight: 1
        $x_1_6 = "bwReobfuscate" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_RK_2147818978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.RK!MTB"
        threat_id = "2147818978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell wget https://bit.ly/3uNrtcg -O pin.txt" ascii //weight: 1
        $x_1_2 = "DownloadString('https://bit.ly/3uLJ706')" ascii //weight: 1
        $x_1_3 = "/home/keith/builds/mingw/gcc-9.2.0-mingw32-cross-native/mingw32/libgcc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_RK_2147818978_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.RK!MTB"
        threat_id = "2147818978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 17 11 18 9a 13 0a 11 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 17 28 ?? ?? ?? 0a 2d 07 17 0b 38 ?? ?? ?? 00 11 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 19 6f ?? ?? ?? 0a 2c 70 11 0a 17 8d ?? ?? ?? 01 13 19 11 19 16 72 ?? ?? ?? 70 a2 11 19 18 17 6f ?? ?? ?? 0a 13 0b 11 0b 8e 69 18 2e 2f 72 ?? ?? ?? 70}  //weight: 1, accuracy: Low
        $x_1_2 = "JFByb2dyZXNzUHJlZmVyZW5jZSA9ICJTaWxlbnRseUNvbnRpbnVlIg0KaWYoJGVudjpQYXRoLkNvbnRhaW5zKCJqYXZhIikpew0KICAgIGlmKF" ascii //weight: 1
        $x_1_3 = "CredUIPromptForCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_ABM_2147832742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.ABM!MTB"
        threat_id = "2147832742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 bf a3 3f 09 0f 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 0a 01 00 00 f7 00 00 00 f3 02 00 00 a1 06 00 00 4d 08 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "fcf0fef2f48940dcc09aab3883193091" wide //weight: 1
        $x_1_6 = "#=zVty8OeKa4qn11BBiWsaFa$hA4Spy" ascii //weight: 1
        $x_1_7 = "#=zC23wgLjk9R1QtaYL_XeFtS6twt4z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_SPQ_2147837092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.SPQ!MTB"
        threat_id = "2147837092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 08 94 58 20 00 01 00 00 5d 94 13 0a 11 06 06 11 04 06 91 11 0a 61 d2 9c 06 17}  //weight: 3, accuracy: High
        $x_2_2 = "palacewpolsce.pl/images/Qvctdry.jpeg" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_ABFR_2147837171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.ABFR!MTB"
        threat_id = "2147837171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 8f 06 ?? ?? 01 25 47 06 07 06 8e 69 5d 91 07 1f 63 58 06 8e 69 58 1f 1f 5f 63 d2 61 d2 52 07 17 58 0b 07 02 8e 69 32 d6}  //weight: 2, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_SPAD_2147840563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.SPAD!MTB"
        threat_id = "2147840563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dtmoulding.com/wander/Qfuud.bmp" wide //weight: 1
        $x_1_2 = "Tlkcsxkfbsjpirxvmcsidxo.Ahnhbqdznm" wide //weight: 1
        $x_1_3 = "GetByteArrayAsync" ascii //weight: 1
        $x_1_4 = "ToByte" ascii //weight: 1
        $x_1_5 = "CreateDelegate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_ABOK_2147842974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.ABOK!MTB"
        threat_id = "2147842974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 16 fe 01 0c 08 2c 19 7e ?? ?? ?? 04 28 ?? ?? ?? 06 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0b 07 0a 2b 01 00 06 2a 33 00 28 ?? ?? ?? 06 72 ?? ?? ?? 70 16 28}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Metropolis_Launcher.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_SJK_2147850512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.SJK!MTB"
        threat_id = "2147850512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Split" ascii //weight: 1
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "CaesarEncrypt" ascii //weight: 1
        $x_1_5 = "InitializeComponent" ascii //weight: 1
        $x_1_6 = "CallByName" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_SJKL_2147850513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.SJKL!MTB"
        threat_id = "2147850513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "quanlykho.Properties" ascii //weight: 1
        $x_1_2 = "dangnhap" ascii //weight: 1
        $x_1_3 = "Bitmap" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "ReverseString" ascii //weight: 1
        $x_1_6 = "BindingFlags" ascii //weight: 1
        $x_1_7 = "InitializeComponent" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_ABGZ_2147896499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.ABGZ!MTB"
        threat_id = "2147896499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 02 16 11 02 8e 69 6f ?? ?? ?? 0a 13 05 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 28 ?? ?? ?? 06 13 02 38 ?? ?? ?? ff dd ?? ?? ?? 00 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = "Exvxtwndd" wide //weight: 1
        $x_1_3 = "Dkkqbl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_SGA_2147900245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.SGA!MTB"
        threat_id = "2147900245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_2 = "My.MyProject.Forms" ascii //weight: 1
        $x_1_3 = "$1830b703-4068-4094-b0f9-6d456b6f7e86" ascii //weight: 1
        $x_1_4 = "get_RequestingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_MVT_2147900848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.MVT!MTB"
        threat_id = "2147900848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 28 44 00 00 06 6f 48 00 00 06 72 de 0d 00 70 28 28 00 00 0a 08 72 f4 0d 00 70 28 28 00 00 0a 6f 3c 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\workspace\\mudfix\\attach\\screen_block\\general\\obj\\Release\\general.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_MC_2147901837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.MC!MTB"
        threat_id = "2147901837"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 02 02 7b ?? ?? ?? 04 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 7d ?? ?? ?? 04 02 73 ?? ?? ?? 0a 7d ?? ?? ?? 04 02 7b ?? ?? ?? 04 20 80 00 00 00 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 06 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 18 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 17 6f ?? ?? ?? 0a 1f 10 8d ?? 00 00 01 0b 02 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 28 ?? ?? ?? 06 07 6f ?? ?? ?? 0a 7d ?? ?? ?? 04 02 7b ?? ?? ?? 04 2d 1d 02 20 00 08 00 00 8d ?? 00 00 01 7d ?? ?? ?? 04 02 1f 10 8d 9f 00 00 01 7d ?? ?? ?? 04 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Enqueue" ascii //weight: 1
        $x_1_3 = "Dequeue" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "BadPasswordException" ascii //weight: 1
        $x_1_6 = "SelfExtractorFlavor" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "get_TotalPhysicalMemory" ascii //weight: 1
        $x_1_9 = "get_Is64BitOperatingSystem" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "UsesEncryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_SIK_2147928023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.SIK!MTB"
        threat_id = "2147928023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://xianggrhen.com/composure/" ascii //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_SLP_2147935038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.SLP!MTB"
        threat_id = "2147935038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 72 ff 06 00 70 6f 95 00 00 0a 75 2b 00 00 01 0b 73 00 01 00 0a 0c 20 00 0e 01 00 0d 07 08 09 28 46 00 00 06 00 d0 46 00 00 01 28 50 00 00 0a 06 72 09 07 00 70 6f 01 01 00 0a 20 00 01 00 00 14 14 17 8d 08 00 00 01 25 16 08 6f 02 01 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {0a 02 03 04 28 47 00 00 06 00 06 7e 4c 00 00 04 25 2d 17 26 7e 49 00 00 04 fe 06 6d 00 00 06 73 d0 00 00 0a 25 80 4c 00 00 04}  //weight: 1, accuracy: High
        $x_1_3 = "FileManager.Form01.resources" ascii //weight: 1
        $x_1_4 = "CSVProject.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tnega_SLD_2147935820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tnega.SLD!MTB"
        threat_id = "2147935820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 72 ff 06 00 70 6f 95 00 00 0a 75 2b 00 00 01 0b 73 00 01 00 0a 0c 20 00 0e 01 00 0d 07 08 09 28 46 00 00 06 00 d0 46 00 00 01 28 50 00 00 0a 06 72 09 07 00 70 6f 01 01 00 0a 20 00 01 00 00 14 14 17 8d 08 00 00 01 25 16 08 6f 02 01 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


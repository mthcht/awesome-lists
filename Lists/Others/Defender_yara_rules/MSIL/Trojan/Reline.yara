rule Trojan_MSIL_Reline_MR_2147782919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.MR!MTB"
        threat_id = "2147782919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_17_1 = {fe 0c 01 00 fe [0-3] 6f [0-4] fe [0-3] 6f [0-4] 28 [0-4] 28 [0-4] fe [0-3] fe [0-3] 6f [0-4] fe [0-3] 6f [0-4] dd}  //weight: 17, accuracy: Low
        $x_1_2 = "Narivia.SelectionRangeConverter.resources" ascii //weight: 1
        $x_1_3 = "$29fad793-56a7-4804-b6ce-02af8b1f5edb" ascii //weight: 1
        $x_1_4 = "NariviaClass" ascii //weight: 1
        $x_1_5 = "GZipStream" ascii //weight: 1
        $x_1_6 = "CopyTo" ascii //weight: 1
        $x_1_7 = "UnaryOperation" ascii //weight: 1
        $x_1_8 = "BinaryOperation" ascii //weight: 1
        $x_1_9 = "GetManifestResourceStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_17_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Reline_V_2147786249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.V!MTB"
        threat_id = "2147786249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AllWalletsRule" ascii //weight: 1
        $x_1_2 = "CoinomiRule" ascii //weight: 1
        $x_1_3 = "JaxxRule" ascii //weight: 1
        $x_1_4 = "ArmoryRule" ascii //weight: 1
        $x_1_5 = "ProtonVPNRule" ascii //weight: 1
        $x_1_6 = "ExodusRule" ascii //weight: 1
        $x_1_7 = "ElectrumRule" ascii //weight: 1
        $x_1_8 = "GuardaRule" ascii //weight: 1
        $x_1_9 = "AtomicRule" ascii //weight: 1
        $x_1_10 = "ScannedBrowser" ascii //weight: 1
        $x_1_11 = "ScannedCookie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_FIOR_2147788493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.FIOR!MTB"
        threat_id = "2147788493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://194.226.139.141" wide //weight: 1
        $x_1_2 = "MemReduct.Main.TaskLoggingHelper" ascii //weight: 1
        $x_1_3 = "$ce9537f3-4b97-4085-8165-8ed2b274e00e" ascii //weight: 1
        $x_1_4 = "$6380BCFF-41D3-4B2E-8B2E-BF8A6810C848" ascii //weight: 1
        $x_1_5 = "$42843719-DB4C-46C2-8E7C-64F1816EFD5B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_BZ_2147789435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.BZ!MTB"
        threat_id = "2147789435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "btnAlchemyLab.Image" wide //weight: 1
        $x_1_2 = "World Radio" wide //weight: 1
        $x_1_3 = "CookieClickerClone.Resources.resources" ascii //weight: 1
        $x_1_4 = "$0156a3dc-6c57-44ce-9176-2d5b1b6e2ba2" ascii //weight: 1
        $x_1_5 = "btnAntimatterCondenser.Image" wide //weight: 1
        $x_1_6 = "btnFarm.Image" wide //weight: 1
        $x_1_7 = "btnGrandma.Image" wide //weight: 1
        $x_1_8 = "btnTimeMachine.Image" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_DGB_2147793001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.DGB!MTB"
        threat_id = "2147793001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr_0_M_e" ascii //weight: 1
        $x_1_2 = "FileZilla" ascii //weight: 1
        $x_1_3 = "Gecko" ascii //weight: 1
        $x_1_4 = "NordApp" ascii //weight: 1
        $x_1_5 = "StringDecrypt" ascii //weight: 1
        $x_1_6 = "RecoursiveFileGrabber" ascii //weight: 1
        $x_1_7 = "AllWalletsRule" ascii //weight: 1
        $x_1_8 = "ArmoryRule" ascii //weight: 1
        $x_1_9 = "AtomicRule" ascii //weight: 1
        $x_1_10 = "CoinomiRule" ascii //weight: 1
        $x_1_11 = "DesktopMessangerRule" ascii //weight: 1
        $x_1_12 = "DiscordRule" ascii //weight: 1
        $x_1_13 = "ElectrumRule" ascii //weight: 1
        $x_1_14 = "EthRule" ascii //weight: 1
        $x_1_15 = "E_x0_d_u_S" ascii //weight: 1
        $x_1_16 = "GuardaRule" ascii //weight: 1
        $x_1_17 = "OpenVPNRule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_OZ_2147793099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.OZ!MTB"
        threat_id = "2147793099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 68 00 79 00 73 00 69 00 63 00 [0-2] 63 00 72 00 61 00 66 00 74 00 2e 00 75 00 73 00 2f 00 4d 00 69 00 6e 00 65 00 63 00 72 00 61 00 66 00 74 00 [0-18] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadFile;component/mainwindow.xaml" wide //weight: 1
        $x_1_3 = "DownloadFileAsync" ascii //weight: 1
        $x_1_4 = "add_DownloadFileCompleted" ascii //weight: 1
        $x_1_5 = "_contentLoaded" ascii //weight: 1
        $x_1_6 = "set_UseShellExecute" ascii //weight: 1
        $x_1_7 = "linq" ascii //weight: 1
        $x_1_8 = "FILENAME" ascii //weight: 1
        $x_1_9 = "set_StartupUri" ascii //weight: 1
        $x_1_10 = "DownloadFile.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_AES_2147793761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.AES!MTB"
        threat_id = "2147793761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C_h_r_o_m_e" ascii //weight: 1
        $x_1_2 = "FileZilla" ascii //weight: 1
        $x_1_3 = "Gecko" ascii //weight: 1
        $x_1_4 = "NordApp" ascii //weight: 1
        $x_1_5 = "RecoursiveFileGrabber" ascii //weight: 1
        $x_1_6 = "AllWalletsRule" ascii //weight: 1
        $x_1_7 = "ArmoryRule" ascii //weight: 1
        $x_1_8 = "AtomicRule" ascii //weight: 1
        $x_1_9 = "CoinomiRule" ascii //weight: 1
        $x_1_10 = "DiscordRule" ascii //weight: 1
        $x_1_11 = "ElectrumRule" ascii //weight: 1
        $x_1_12 = "EthRule" ascii //weight: 1
        $x_1_13 = "ExodusRule" ascii //weight: 1
        $x_1_14 = "GameLauncherRule" ascii //weight: 1
        $x_1_15 = "GuardaRule" ascii //weight: 1
        $x_1_16 = "OpenVPNRule" ascii //weight: 1
        $x_1_17 = "ProtonVPNRule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_BF_2147796247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.BF!MTB"
        threat_id = "2147796247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr_0_M_e" ascii //weight: 1
        $x_1_2 = "FileZilla" ascii //weight: 1
        $x_1_3 = "g_E_c_" ascii //weight: 1
        $x_1_4 = "CryptoHelper" ascii //weight: 1
        $x_1_5 = "AllWallets" ascii //weight: 1
        $x_1_6 = "OpenVPN" ascii //weight: 1
        $x_1_7 = "WalletConfig" ascii //weight: 1
        $x_1_8 = "ScannedCookie" ascii //weight: 1
        $x_1_9 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 1
        $x_1_10 = "TryInitColdWallets" ascii //weight: 1
        $x_1_11 = "TryInitDiscord" ascii //weight: 1
        $x_1_12 = "TryInitNordVPN" ascii //weight: 1
        $x_1_13 = "get_ScanGeckoBrowsersPaths" ascii //weight: 1
        $x_1_14 = "get_FtpConnections" ascii //weight: 1
        $x_1_15 = "asdk9345asd" ascii //weight: 1
        $x_1_16 = "kkdhfakdasd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_RPQ_2147796514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.RPQ!MTB"
        threat_id = "2147796514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "TanasittxProtector v9999999" ascii //weight: 10
        $x_2_2 = {68 00 74 00 74 00 70 (00|00) 3a 00 2f 00 2f}  //weight: 2, accuracy: Low
        $x_1_3 = {2d 47 00 65 00 74 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65}  //weight: 1, accuracy: High
        $x_1_4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Reline_IYZ_2147796834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.IYZ!MTB"
        threat_id = "2147796834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OUTPUT-ONLINEPNGTOOLS" wide //weight: 1
        $x_1_2 = "fidasiaso" wide //weight: 1
        $x_1_3 = "sdfkfddfs.exe" wide //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "HttpWebRequest" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_BE_2147797796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.BE!MTB"
        threat_id = "2147797796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TryInitNordVPN" ascii //weight: 1
        $x_1_2 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 1
        $x_1_3 = "GeckoRoamingName" ascii //weight: 1
        $x_1_4 = "ChromeGetRoamingName" ascii //weight: 1
        $x_1_5 = "Chr_0_M_e" ascii //weight: 1
        $x_1_6 = "TryInitDiscord" ascii //weight: 1
        $x_1_7 = "dvsjiohq3" ascii //weight: 1
        $x_1_8 = "gkdsi8y234" ascii //weight: 1
        $x_1_9 = "adkasd8u3hbasd" ascii //weight: 1
        $x_1_10 = "kkdhfakdasd" ascii //weight: 1
        $x_1_11 = "asdasod9234oasd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_EX_2147798772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.EX!MTB"
        threat_id = "2147798772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<3fd42953-6a25-4639-ad70-080d9f7a6082_netmodule>" ascii //weight: 1
        $x_1_2 = "<394d8dc8-4869-402c-ac12-b5e353e85355_netmodule>" ascii //weight: 1
        $x_1_3 = "<e4effeae-1e10-4239-9cc0-2e7de19fce75_netmodule>" ascii //weight: 1
        $x_1_4 = "<2c4509e9-ec15-4bbd-b3d1-b96af8133da7_netmodule>" ascii //weight: 1
        $x_1_5 = "<23892db2-51f1-4c7d-bd1a-9aa4e2dab1d8_netmodule>" ascii //weight: 1
        $x_1_6 = "<06953af8-dba9-4378-acff-d219f2961fb9_netmodule>" ascii //weight: 1
        $x_1_7 = "<6fb280c8-2726-48c4-bddb-3e881ce5000b_netmodule>" ascii //weight: 1
        $x_1_8 = "<59ecad5b-785d-4cd5-84a7-cdefe18516bb_netmodule>" ascii //weight: 1
        $x_1_9 = "<c3b68a12-ad3b-47e8-b7cb-2d3768ee0e4d_netmodule>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_ABZ_2147829259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.ABZ!MTB"
        threat_id = "2147829259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {57 97 a2 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 61 00 00 00 22 00 00 00 25 00 00 00 6e 00 00 00 09 00 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "get_IsBrowserHosted" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "FlushFinalBlock" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_ABS_2147829262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.ABS!MTB"
        threat_id = "2147829262"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 d5 a2 2b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6e 00 00 00 76 00 00 00 fb 00 00 00 8a 01 00 00 f6 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "oTcNAY@fetcHjhKoGtecR" ascii //weight: 1
        $x_1_3 = "tcJmja5[tcJmVaM" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "GetRuntimeDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_RDB_2147849150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.RDB!MTB"
        threat_id = "2147849150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "130e7fd2-4955-45b3-96db-559d9639baea" ascii //weight: 1
        $x_1_2 = "ZeddMenuLauncher" ascii //weight: 1
        $x_2_3 = {11 2f 11 37 8f 39 00 00 01 25 4b 11 38 61 54 11 39}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_SSN_2147920104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.SSN!MTB"
        threat_id = "2147920104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 20 02 11 20 91 66 d2 9c 02 11 20 8f 2b 00 00 01 25 71 2b 00 00 01 20 82 00 00 00 58 d2 81 2b 00 00 01 02 11 20 8f 2b 00 00 01 25 71 2b 00 00 01 1f 44 59 d2 81 2b 00 00 01 00 11 20 17 58 13 20 11 20 02 8e 69 fe 04 13 21 11 21 2d b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_EC_2147920858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.EC!MTB"
        threat_id = "2147920858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pimer.bbbcontents7.My.Resources" ascii //weight: 1
        $x_1_2 = "pimer.bbbcontents7.pdb" ascii //weight: 1
        $x_1_3 = "aBVIn5mUIYK4EYrhHd" ascii //weight: 1
        $x_1_4 = "TaskSchedulerResumeWithAwaitable" ascii //weight: 1
        $x_1_5 = "TaskResumeWithAwaitable" ascii //weight: 1
        $x_1_6 = "TaskAwaiterWithOptions" ascii //weight: 1
        $x_1_7 = "TaskSchedulerAwaiter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_MBXT_2147921075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.MBXT!MTB"
        threat_id = "2147921075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 53 41 64 46 46 43 56 4d 65 4a 51 50 62 55 33 74 4d 00 77 68 36 65 37 55 66 57 70 43 6e 59}  //weight: 1, accuracy: High
        $x_1_2 = {44 36 4b 56 00 4c 6f 61 64 4c}  //weight: 1, accuracy: High
        $x_1_3 = "Ads_multysave.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Reline_BAA_2147946314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Reline.BAA!MTB"
        threat_id = "2147946314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 04 06 11 04 91 07 11 04 09 5d ?? ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 df}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


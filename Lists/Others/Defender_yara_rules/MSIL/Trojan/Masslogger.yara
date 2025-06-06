rule Trojan_MSIL_Masslogger_VN_2147758432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.VN!MTB"
        threat_id = "2147758432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 73 ?? ?? ?? 06 0a 02 28 ?? ?? ?? 06 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Masslogger_VN_2147758432_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.VN!MTB"
        threat_id = "2147758432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 0c 19 8d ?? ?? ?? 01 25 16 06 a2 25 17 07 a2 25 18 08 a2 73 ?? ?? ?? 06 0d 2a 10 00 7e ?? ?? ?? 04 0a 7e ?? ?? ?? 04 0b 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Masslogger_VN_2147758432_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.VN!MTB"
        threat_id = "2147758432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 d2 9c 1e 00 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 91 fe ?? ?? 00 61 fe ?? ?? 00 fe ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Masslogger_VN_2147758432_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.VN!MTB"
        threat_id = "2147758432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 0b 19 8d ?? ?? ?? 01 25 16 06 a2 25 17 07 a2 25 18 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 a2 73 ?? ?? ?? 06 26 2a 0a 00 7e ?? ?? ?? 04 0a 7e}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 14 0c 19 8d ?? ?? ?? 01 25 16 06 a2 25 17 07 a2 25 18 72 ?? ?? ?? 70 a2 73 ?? ?? ?? 06 0d 2a 0b 00 7e ?? ?? ?? 04 0a 7e ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Masslogger_VN_2147758432_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.VN!MTB"
        threat_id = "2147758432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URL=file://zzSOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 [0-30] 5c 00 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 [0-30] 5c 52 65 67 41 73 6d 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "PasswordHash" ascii //weight: 1
        $x_1_5 = "get_StartupPath" ascii //weight: 1
        $x_1_6 = "TASKKILkilll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_Masslogger_K_2147758915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.K!MTB"
        threat_id = "2147758915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BombMine" ascii //weight: 1
        $x_1_2 = "KWpvO.exe" ascii //weight: 1
        $x_1_3 = "http://tempuri.org/DataSet1.xsd" ascii //weight: 1
        $x_1_4 = "Pong Game by Paula" ascii //weight: 1
        $x_1_5 = "quarantinee4" ascii //weight: 1
        $x_1_6 = "jtnJD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_Masslogger_SS_2147769638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.SS!MTB"
        threat_id = "2147769638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FolderOrganiser.FolderOrganiserForm.resources" ascii //weight: 1
        $x_1_2 = "Pixel_Density.FormDensity.resources" ascii //weight: 1
        $x_1_3 = "Pixel_Density.FormIntro.resources" ascii //weight: 1
        $x_1_4 = "FolderOrganiser.InvalidPath.resources" ascii //weight: 1
        $x_1_5 = "checkInternet.LoginForm.resources" ascii //weight: 1
        $x_1_6 = "Timer.MainWindow.resources" ascii //weight: 1
        $x_1_7 = "FolderOrganiser.NoFiles.resources" ascii //weight: 1
        $x_1_8 = "FolderOrganiser.NoRadioButtonSelected.resources" ascii //weight: 1
        $x_1_9 = "Timer.OptionsWindow.resources" ascii //weight: 1
        $x_1_10 = "winform_pagination.ExtPagination.resources" ascii //weight: 1
        $x_1_11 = "FolderOrganiser.Properties.Resources.resources" ascii //weight: 1
        $x_1_12 = "winform_pagination.Sample.resources" ascii //weight: 1
        $x_1_13 = "get_qqqqqqqqqqqqqqqqqqqqqqqqqqqqq" ascii //weight: 1
        $x_1_14 = "GetEnvironmentVariable" ascii //weight: 1
        $x_1_15 = "IPStatus" ascii //weight: 1
        $x_1_16 = "CreateInstance" ascii //weight: 1
        $x_1_17 = "AppDomain" ascii //weight: 1
        $x_1_18 = "get_CurrentDomain" ascii //weight: 1
        $x_1_19 = "get_SelectedPath" ascii //weight: 1
        $x_1_20 = "BlockCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Masslogger_A_2147770246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.A!ibt"
        threat_id = "2147770246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ROOT\\SecurityCenter" ascii //weight: 1
        $x_1_2 = "AntivirusProduct" ascii //weight: 1
        $x_1_3 = "AntiSpyWareProduct" ascii //weight: 1
        $x_1_4 = "/C ping 127.0.0.1 -n 3 > nul & del" ascii //weight: 1
        $x_10_5 = "monero-project" ascii //weight: 10
        $x_10_6 = "\\Ethereum\\wallets" ascii //weight: 10
        $x_10_7 = "settingsCoinomi\\wallet_db" ascii //weight: 10
        $x_1_8 = "Chrome/FirewallProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Masslogger_GG_2147773252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.GG!MTB"
        threat_id = "2147773252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "masslogger" ascii //weight: 15
        $x_1_2 = "Password" ascii //weight: 1
        $x_1_3 = "SetWindowsHookEx" ascii //weight: 1
        $x_1_4 = "GetKeyboardState" ascii //weight: 1
        $x_1_5 = "CallNextHookEx" ascii //weight: 1
        $x_1_6 = "HOOK/MEMORY6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Masslogger_GG_2147773252_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.GG!MTB"
        threat_id = "2147773252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "MassLoggerBin" ascii //weight: 20
        $x_1_2 = "Costura" ascii //weight: 1
        $x_1_3 = "WM_CLIPBOARDUPDATE" ascii //weight: 1
        $x_1_4 = "WHKEYBOARDLL" ascii //weight: 1
        $x_1_5 = "SetWindowsHookEx" ascii //weight: 1
        $x_1_6 = "loggerData" ascii //weight: 1
        $x_1_7 = "Keylogger" ascii //weight: 1
        $x_1_8 = "AntiSandboxie" ascii //weight: 1
        $x_1_9 = "AntiVMware" ascii //weight: 1
        $x_1_10 = "SpreadUsb" ascii //weight: 1
        $x_1_11 = "Screenshot" ascii //weight: 1
        $x_1_12 = "BotKiller" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Masslogger_MS_2147777850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.MS!MTB"
        threat_id = "2147777850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Professional_Editor.FindReplace.resources" ascii //weight: 1
        $x_1_2 = "Professional_Editor.CoreMain.resources" ascii //weight: 1
        $x_1_3 = "svaeToolStripMenuItem_Click" ascii //weight: 1
        $x_1_4 = "ClipboardClass" ascii //weight: 1
        $x_1_5 = "NextFind" ascii //weight: 1
        $x_1_6 = "RTBMain" ascii //weight: 1
        $x_1_7 = "fldFilePatch" ascii //weight: 1
        $x_1_8 = "ContentChanged" ascii //weight: 1
        $x_1_9 = "fldContent" ascii //weight: 1
        $x_1_10 = "INIManager" ascii //weight: 1
        $x_1_11 = "changeToolStripMenuItem" ascii //weight: 1
        $x_1_12 = "openToolStripMenuItem" ascii //weight: 1
        $x_1_13 = "fileToolStripMenuItem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Trojan_MSIL_Masslogger_HHQ_2147935728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.HHQ!MTB"
        threat_id = "2147935728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d}  //weight: 6, accuracy: Low
        $x_5_2 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0c 16 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Masslogger_SWA_2147936226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.SWA!MTB"
        threat_id = "2147936226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 06 11 0f 11 0f 1b 5a 20 bb 00 00 00 61 d2 9c 00 11 0f 17 58 13 0f 11 0f 11 06 8e 69 fe 04 13 10 11 10 2d da}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Masslogger_MBV_2147937104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.MBV!MTB"
        threat_id = "2147937104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 04 06 11 04 19 5a 58 1f 18 5d 1f 0c 59 9e 11 04 17 58 13 04 11 04 07 8e 69 fe 04}  //weight: 1, accuracy: High
        $x_1_2 = {4b 00 49 00 00 09 4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 00 25 4c 00 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Masslogger_ZSY_2147939137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.ZSY!MTB"
        threat_id = "2147939137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 72 47 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Masslogger_ZET_2147942956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Masslogger.ZET!MTB"
        threat_id = "2147942956"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {25 16 03 6f ?? 01 00 0a 0a 12 00 20 53 01 00 00 20 0c 01 00 00 28 ?? 00 00 06 9c 25 17 03 6f ?? 01 00 0a 0a 12 00 28 ?? 00 00 0a 9c 25 18 03}  //weight: 6, accuracy: Low
        $x_5_2 = {9c 2b 21 19 8d ?? 00 00 01 25 16 03 6f ?? 01 00 0a 9c 25 17 03 6f ?? 01 00 0a 9c 25 18 03 6f ?? 01 00 0a 9c 73 ?? 01 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


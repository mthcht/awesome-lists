rule Trojan_MSIL_Remcos_2147754020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos!MTB"
        threat_id = "2147754020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {73 12 00 00 06 25 28 19 00 ?? ?? 28 04 00 ?? ?? 28 0b 00 ?? ?? 7d 05 00 ?? ?? 13 01 20 00 00 ?? ?? 7e 2c 00 ?? ?? 7b 4b 00 ?? ?? 3a b0 ff ?? ?? 26 20 00 00 ?? ?? 38 a5 ff ff ff}  //weight: 6, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PA_2147754828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PA!MTB"
        threat_id = "2147754828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-2] 44 00 49 00 53 00 50 00 41 00 52 00 45 00 41 00 [0-2] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-2] 2f 00 63 00 20 00 52 00 45 00 47 00 20 00 41 00 44 00 44 00 20 00 [0-2] 20 00 2f 00 66 00 20 00 2f 00 76 00 20 00 [0-2] 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 [0-2] 22 00 20 00 2d 00 61 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {61 00 76 00 70 00 [0-2] 62 00 64 00 61 00 67 00 65 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = "SUPRAVEGHEREREG" wide //weight: 1
        $x_1_5 = "SUPRAVEGHERENSEI" wide //weight: 1
        $x_1_6 = "REVEDUIVM" wide //weight: 1
        $x_1_7 = "IMAGINEPREVENIRE" wide //weight: 1
        $x_1_8 = "Virtual environment detected!" wide //weight: 1
        $x_1_9 = "svchost.exe" wide //weight: 1
        $x_1_10 = "AppLaunch.exe" wide //weight: 1
        $x_1_11 = "mscorsvw.exe" wide //weight: 1
        $x_1_12 = "InstallUtil.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SD_2147759124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SD!MTB"
        threat_id = "2147759124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 20 00 00 0a 0d 02 6f 21 00 00 0a 0b 03 6f 21 00 00 0a 13 04 73 22 00 00 0a 0c 08 28 23 00 00 0a 03 6f 24 00 00 0a 6f 25 00 00 0a 13 06 16 13 05 16 02 6f 26 00 00 0a 17 da 13 0a 13 08 2b 49 02 11 08 18 6f 27 00 00 0a 1f 10 28 28 00 00 0a 11 06 11 05 91 61 28 29 00 00 0a 13 09 09 11 09 6f 2a 00 00 0a 26 11 05 03 6f 26 00 00 0a 17 da fe 01 13 07 11 07 2c 05 16 13 05 2b 06 11 05 17 d6 13 05 11 08 18 d6 13 08 11 08 11 0a 31 b1 09 6f 2b 00 00 0a 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_A_2147759488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.A!MTB"
        threat_id = "2147759488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 72 0f 00 00 70 6f 1c 00 00 0a 14 17 8d 01 00 00 01 25 16 02 a2 28 22 00 00 06 2a}  //weight: 2, accuracy: High
        $x_2_2 = {7e 02 00 00 04 2d 1e 72 21 00 00 70 d0 0b 00 00 02 28 3f 00 00 06 6f 32 00 00 0a 73 33 00 00 0a 80 02 00 00 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_A_2147759488_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.A!MTB"
        threat_id = "2147759488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RPF:SmartAssembly" ascii //weight: 1
        $x_1_2 = "nhffskdsfkdddfdhdafffdddfdddhgfsdscffdf" ascii //weight: 1
        $x_1_3 = "hkgfsfdffdhfhddfdrfahghddsshcf" ascii //weight: 1
        $x_1_4 = "chfddgefffghkdaffsfhdddhdshdghf" ascii //weight: 1
        $x_1_5 = "sddddffsfheghddjfffffgjhskdggsfaafcsafp" ascii //weight: 1
        $x_1_6 = "sfhjffkfhgfdjsrfhhddfhfffadsgfasfhsscffgdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AQ_2147766265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AQ!MTB"
        threat_id = "2147766265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 1f fe 0a 18 0c 1f 0c 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e 03 0a 6f 04 0a 7e 03 0a 6f 04 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e 03 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e 03 0a 6f 04 0a 7e 03 0a 6f 04 0a 7e 03 0a 6f 04 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e 03 0a 6f 04 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e 03 0a 6f 04 0a 7e 03 0a 6f 04 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e 03 0a 6f 04 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e 03 0a 6f ?? ?? ?? 0a 7e 03 0a 6f 04 0a 7e 03 0a 6f 04 0a 7e 03 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a a2 25 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FG_2147766788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FG!MTB"
        threat_id = "2147766788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Davide Homepage" ascii //weight: 1
        $x_1_2 = "davidemauri.it" ascii //weight: 1
        $x_1_3 = "regexlib" ascii //weight: 1
        $x_1_4 = "Holy Shit" ascii //weight: 1
        $x_1_5 = "RegEx CheatSheet" ascii //weight: 1
        $x_1_6 = "CSharpSnippet" ascii //weight: 1
        $x_1_7 = "opablo@gmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FH_2147767201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FH!MTB"
        threat_id = "2147767201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {07 08 06 09 93 9d 00 08 17 58 0c 09 17 59 0d 08 02 6f ?? ?? ?? 0a fe 04 13 04 11 04 2d e1}  //weight: 20, accuracy: Low
        $x_1_2 = {00 61 61 61 61 61 61 61 00}  //weight: 1, accuracy: High
        $x_1_3 = "ReverseStuff" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Decompress" ascii //weight: 1
        $x_1_6 = "Compress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FJ_2147767879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FJ!MTB"
        threat_id = "2147767879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$17dbf9f5-7e15-46ac-b4cc-a52a3d9cd807" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_DA_2147773116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.DA!MTB"
        threat_id = "2147773116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$493b940d-3ee6-42b1-8612-20d025704f2b" ascii //weight: 5
        $x_5_2 = "pictureBox10_Click" ascii //weight: 5
        $x_5_3 = "checkBox10" ascii //weight: 5
        $x_5_4 = "recover10" ascii //weight: 5
        $x_5_5 = "textBox10" ascii //weight: 5
        $x_5_6 = "copy10" ascii //weight: 5
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_9 = "get_CurrentDomain" ascii //weight: 1
        $x_1_10 = "IsLogging" ascii //weight: 1
        $x_1_11 = "get_Red" ascii //weight: 1
        $x_1_12 = "set_FormattingEnabled" ascii //weight: 1
        $x_1_13 = "DbCommand" ascii //weight: 1
        $x_1_14 = "set_BackgroundImage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_ZA_2147773171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZA!MTB"
        threat_id = "2147773171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_panelMIS" ascii //weight: 1
        $x_1_2 = "add_Shutdown" ascii //weight: 1
        $x_1_3 = "Lerlibro_INC.ucUsers.resources" ascii //weight: 1
        $x_1_4 = "$111ad02b-cccd-4106-b328-93b3adb05e52" ascii //weight: 1
        $x_1_5 = "txtPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GA_2147773254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GA!MTB"
        threat_id = "2147773254"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//107.189.4.70/693.bin" ascii //weight: 1
        $x_1_2 = "Jioz.NewFileForm.resources" ascii //weight: 1
        $x_1_3 = "Jioz.PropertiesForm.resources" ascii //weight: 1
        $x_1_4 = "HttpWebResponse" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GA_2147773254_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GA!MTB"
        threat_id = "2147773254"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "%systemroot%\\Microsoft.NET\\Framework\\v4.0.30319\\AddInProcess32.exe" ascii //weight: 10
        $x_10_2 = {74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-20] 2e 00 [0-30] 2e 00 72 00 75 00 2f 00 [0-40] 96 00 68 00}  //weight: 10, accuracy: Low
        $x_10_3 = {74 74 70 73 3a 2f 2f [0-20] 2e [0-30] 2e 72 75 2f [0-40] 96 00 68}  //weight: 10, accuracy: Low
        $x_1_4 = "set_UseShellExecute" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "SystemNetworkCredentiall" ascii //weight: 1
        $x_1_8 = "e_lfanew" ascii //weight: 1
        $x_1_9 = "SecurityCryptographyCAPIBaseCERT" ascii //weight: 1
        $x_1_10 = "Location" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_GB_2147773255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GB!MTB"
        threat_id = "2147773255"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "%systemroot%\\Microsoft.NET\\Framework\\v4.0.30319\\AddInProcess32.exe" ascii //weight: 10
        $x_10_2 = {74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-20] 2e 00 [0-30] 2e 00 72 00 75 00 2f 00 [0-40] 96 00 68 00}  //weight: 10, accuracy: Low
        $x_10_3 = {74 74 70 73 3a 2f 2f [0-20] 2e [0-30] 2e 72 75 2f [0-40] 96 00 68}  //weight: 10, accuracy: Low
        $x_1_4 = "Running" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "disConnect" ascii //weight: 1
        $x_1_8 = "SocketShutdown" ascii //weight: 1
        $x_1_9 = "payload" ascii //weight: 1
        $x_1_10 = "Attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_GC_2147773800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GC!MTB"
        threat_id = "2147773800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-4] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "//cdn.discordapp.com/attachments/" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp" ascii //weight: 1
        $x_1_4 = "GetExportedTypes" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "WebClient" ascii //weight: 1
        $x_1_8 = "Reverse" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GC_2147773800_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GC!MTB"
        threat_id = "2147773800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "\\Microsoft.NET\\Framework\\v4.0.30319\\AddInProcess32.exe" ascii //weight: 20
        $x_5_2 = {74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-20] 2e 00 [0-30] 2e 00 72 00 75 00 2f 00 [0-40] 96 00 68 00}  //weight: 5, accuracy: Low
        $x_5_3 = {74 74 70 73 3a 2f 2f [0-20] 2e [0-30] 2e 72 75 2f [0-40] 96 00 68}  //weight: 5, accuracy: Low
        $x_5_4 = {74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-30] 2e 00 72 00 75 00 2f 00 [0-40] 5a 00 68 00}  //weight: 5, accuracy: Low
        $x_5_5 = {74 74 70 73 3a 2f 2f [0-30] 2e 72 75 2f [0-40] 5a 00 68}  //weight: 5, accuracy: Low
        $x_1_6 = "DownloadString" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "set_Expect100Continue" ascii //weight: 1
        $x_1_9 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_YA_2147775617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.YA!MTB"
        threat_id = "2147775617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_BlockSize" ascii //weight: 1
        $x_1_2 = "get_KeySize" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Microsoft.VisualBasic.CompilerServices" ascii //weight: 1
        $x_1_5 = "System.Web.Services.Protocols.SoapHttpClientProtocol" ascii //weight: 1
        $x_1_6 = "SHA1CryptoServiceProvider" ascii //weight: 1
        $x_1_7 = "outCompiled.exe" ascii //weight: 1
        $x_1_8 = "Create__Instance__" ascii //weight: 1
        $x_1_9 = "System.CodeDom.Compiler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RQ_2147776330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RQ!MTB"
        threat_id = "2147776330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggableAttribute" ascii //weight: 1
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "_okqwdoqwkodqw" ascii //weight: 1
        $x_1_4 = "$e7775187-6eee-4ad3-99cd-04e0a59b79dd" ascii //weight: 1
        $x_1_5 = "System.Security" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PB_2147776898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PB!MTB"
        threat_id = "2147776898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$2c60520e-e3cc-4b09-8d11-f25836f995fd" ascii //weight: 20
        $x_20_2 = "$ebda4991-b7fb-4441-9395-88ca2afcf2dc" ascii //weight: 20
        $x_20_3 = "$30d4aa3a-afb6-4765-ba18-f2364470e34f" ascii //weight: 20
        $x_1_4 = "Remote_Administration_Tool.Properties.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "CaptureScreenImage.Properties.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "VB_blackjack.My.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "DebuggerBrowsableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PC_2147777286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PC!MTB"
        threat_id = "2147777286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qwertyuiopasdfghjklzxcvbnm" ascii //weight: 1
        $x_1_2 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "zCom.resources" ascii //weight: 1
        $x_1_5 = "Kolikox" ascii //weight: 1
        $x_1_6 = "GetInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
        $x_1_8 = ".tmp.exe" ascii //weight: 1
        $x_1_9 = "1234567890" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PD_2147777540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PD!MTB"
        threat_id = "2147777540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = "Fedaliruant.Resturnigi.png" ascii //weight: 7
        $x_2_2 = {16 8d 03 00 00 01 14 14 14 28 ?? 01 00 0a 74 15 00 00 1b 13 05 73 7f 01 00 0a 13 07 11 05 8e 69 17 da 13 09 16 13 06 2b 15 11 07 11 06 11 05 11 06 9a 6f ?? 01 00 0a 00 11 06 17 d6 13 06 11 06 11 09 31 e5}  //weight: 2, accuracy: Low
        $x_2_3 = {01 00 0a 13 0a 2b 2d 12 0a 28 ?? 01 00 0a 13 0b 12 0b 28 ?? 01 00 0a 07 6f ?? 01 00 0a 13 0c 11 0c 2c 0f 09 12 0b 28 ?? 01 00 0a 6f ?? 01 00 0a 00 00 00 00 12 0a 28 ?? 01 00 0a 13 0d 11 0d 2d c6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PD_2147777540_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PD!MTB"
        threat_id = "2147777540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$7d0d8341-01a1-458c-ab2f-db79831913c6" ascii //weight: 10
        $x_10_2 = "$bc3f17fb-3eaa-4d4a-8fbe-5261380e04be" ascii //weight: 10
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "PrimeX.Tools.Properties.Resources" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "shutdowntimer.Properties.Resources" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PE_2147777742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PE!MTB"
        threat_id = "2147777742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$6d9dce21-a125-4491-bbb3-8117d48869f1" ascii //weight: 20
        $x_20_2 = "$abaaedd4-5c4c-42de-b5c9-e6b2591f1c09" ascii //weight: 20
        $x_20_3 = "$c2934561-035a-4a99-b861-336f50318173" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "Video_Capture_DonK.Properties.Resources" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "Ddd.Resources.resources" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "BaseConfigHandler.My.Resources" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PH_2147777832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PH!MTB"
        threat_id = "2147777832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 72 ?? ?? ?? 70 28 02 00 00 06 74 01 00 00 1b 0a 72 ?? ?? ?? 70 28 10 00 00 0a 0b 16 0c 2b 13 06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PF_2147778055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PF!MTB"
        threat_id = "2147778055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$b2d90300-7195-4872-be39-bf8851b814b3" ascii //weight: 20
        $x_20_2 = "$334f3be9-0131-4a45-866a-162be9e26fcb" ascii //weight: 20
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "Stub.g.resources" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PI_2147778057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PI!MTB"
        threat_id = "2147778057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 a8 61 00 00 28 13 00 00 0a 28 14 00 00 0a 72 01 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 6f 15 00 00 0a 0a 06 72 19 00 00 70 6f 16 00 00 0a 0b 07 28 17 00 00 0a 0c 7e 01 00 00 04 2d 36 20 00 01 00 00 72 33 00 00 70 14 d0 03 00 00 02 28 18 00 00 0a 17 8d 1a 00 00 01 0d 09 16 16 14 28 19 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PJ_2147778058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PJ!MTB"
        threat_id = "2147778058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 14 72 ?? ?? 01 70 16 8d 05 00 00 01 14 14 14 28 ?? ?? ?? 0a 14 72 ?? ?? 01 70 18 8d 05 00 00 01 0d 09 16 14 a2 00 09 17 14 a2 00 09 14 14 14 17 28 ?? ?? ?? 0a 26 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PK_2147778060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PK!MTB"
        threat_id = "2147778060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 0c 00 00 06 0a 06 74 06 00 00 1b 28 15 00 00 06 0b 28 3a 00 00 0a 07 6f 3b 00 00 0a 0c 08 6f 3c 00 00 0a 17 8c 38 00 00 01 14 6f 3d 00 00 0a 74 3a 00 00 01 28 3e 00 00 0a 0d 2a}  //weight: 5, accuracy: High
        $x_5_2 = {28 1e 00 00 06 0a 06 74 06 00 00 1b 28 1a 00 00 06 0d 28 01 00 00 0a 09 6f 02 00 00 0a 0b 07 6f 03 00 00 0a 17 8c 10 00 00 01 14 6f 04 00 00 0a 74 12 00 00 01 28 05 00 00 0a 0c 00 2a}  //weight: 5, accuracy: High
        $x_5_3 = {28 23 00 00 06 0d 09 74 0c 00 00 1b 28 1f 00 00 06 0a 28 36 00 00 0a 06 6f 37 00 00 0a 0c 08 6f 38 00 00 0a 17 8c 2f 00 00 01 14 6f 39 00 00 0a 74 31 00 00 01 28 3a 00 00 0a 0b 2a}  //weight: 5, accuracy: High
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PL_2147778061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PL!MTB"
        threat_id = "2147778061"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 03 00 00 0a 72 01 00 00 70 6f 04 00 00 0a 0a 06 6f 05 00 00 0a d4 8d 06 00 00 01 0b 06 07 16 07 8e 69 6f 06 00 00 0a 26 07 72 13 00 00 70 28 02 00 00 06 0b 07 28 07 00 00 0a 6f 08 00 00 0a 14 14 6f 09 00 00 0a 26 de 0a 06 2c 06 06 6f 0a 00 00 0a dc 2a}  //weight: 1, accuracy: High
        $x_1_2 = "TempFile" ascii //weight: 1
        $x_1_3 = "#PASSWORD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PM_2147778062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PM!MTB"
        threat_id = "2147778062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 0c 08 6f ?? ?? ?? 0a 26 08 72 ?? ?? ?? 70 15 16 28 ?? ?? ?? 0a 26 08 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 08 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 26 07 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PG_2147778225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PG!MTB"
        threat_id = "2147778225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 0b 07 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 0c 08 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 73}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0d 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 14 18 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a a2 25 17 06 28 ?? ?? ?? 0a a2 6f ?? ?? ?? 0a 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PN_2147778227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PN!MTB"
        threat_id = "2147778227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d4b687de-7d78-426e-9d8a-5ceec7d875cb" ascii //weight: 20
        $x_20_2 = "$54904655-c286-4e39-9434-21e5b57a193c" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "SQLTutorial.Resources.resources" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "ndtia_Live_Server.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PO_2147778325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PO!MTB"
        threat_id = "2147778325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$fc752e85-0cd0-4317-b954-f754068f0fc4" ascii //weight: 20
        $x_20_2 = "$a127bc35-0e29-4939-b03b-5c7ffa56c52f" ascii //weight: 20
        $x_20_3 = "$adb52bbf-ce87-498d-a993-43fa78a5cd63" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "Cards_Interfaces.My.Resources" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "ReflectionExtensions.My.Resources" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "MiniCalc.Resources" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PP_2147778543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PP!MTB"
        threat_id = "2147778543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 06 11 07 6f ?? ?? ?? 0a 13 08 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 2f 0d 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 2f 0d 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 07 17 58 13 07 11 07 07 6f ?? ?? ?? 0a 32 a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PP_2147778543_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PP!MTB"
        threat_id = "2147778543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$AE5E3AFC-9C2E-4C38-AC01-85C199D19F3A" ascii //weight: 20
        $x_20_2 = "$80e20fa3-87ee-4dd6-bf09-d96ba4527144" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "GameProject.My.Resources" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "PM_FormsAvgCalc.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PQ_2147778546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PQ!MTB"
        threat_id = "2147778546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$b3ed296a-ddd4-46b9-853b-3697700caa1d" ascii //weight: 20
        $x_20_2 = "$150476af-3c22-401d-b7ab-7716567cccc6" ascii //weight: 20
        $x_20_3 = "$56ca4612-c38a-4785-9957-051dee84afab" ascii //weight: 20
        $x_20_4 = "$a7720f3d-1cd4-4a64-87cd-1405f2a46b92" ascii //weight: 20
        $x_5_5 = "CreateInstance" ascii //weight: 5
        $x_5_6 = "Activator" ascii //weight: 5
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
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PT_2147778854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PT!MTB"
        threat_id = "2147778854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 06 00 00 06 28 05 00 00 06 6f ?? ?? ?? 0a 0a 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 0c 7e ?? ?? ?? 04}  //weight: 2, accuracy: Low
        $x_2_2 = {20 00 01 00 00 72 ?? ?? ?? 70 14 d0 03 00 00 02 28 ?? ?? ?? 0a 17 8d ?? ?? ?? 01}  //weight: 2, accuracy: Low
        $x_1_3 = {09 20 00 01 00 00 6f ?? ?? ?? 0a 09 20 80 00 00 00 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 04 11 04 07 20 e8 03 00 00 73 ?? ?? ?? 0a 13 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PU_2147778924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PU!MTB"
        threat_id = "2147778924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$cf53de9d-ee81-42c9-9113-d4233e8cefc6" ascii //weight: 20
        $x_1_2 = "PointOfSale.Properties.Resources" ascii //weight: 1
        $x_1_3 = "Graph.Properties.Resources" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PV_2147778929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PV!MTB"
        threat_id = "2147778929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$3ecb6c46-7dbb-4999-bee5-403533a30af7" ascii //weight: 20
        $x_20_2 = "$D359B21A-6AD3-42BB-91B0-4E938C9DEBBC" ascii //weight: 20
        $x_20_3 = "$45802242-81b4-42a5-a0a0-017bf7af26df" ascii //weight: 20
        $x_1_4 = "IdOps.My.Resources" ascii //weight: 1
        $x_1_5 = "FileZillaProject.My.Resources" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_10 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_11 = "DebuggableAttribute" ascii //weight: 1
        $x_1_12 = "DebuggingModes" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
        $x_1_15 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PS_2147779080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PS!MTB"
        threat_id = "2147779080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$e25a04c9-d2e8-46cc-a898-cd7f40c18703" ascii //weight: 20
        $x_20_2 = "$21645c09-4059-416a-a291-701cab173423" ascii //weight: 20
        $x_20_3 = "$74db57f1-964f-463b-a358-e8c37adff80e" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PX_2147779081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PX!MTB"
        threat_id = "2147779081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$9d95c869-fd20-489d-b0aa-838564d2852f" ascii //weight: 20
        $x_20_2 = "$4b07ece7-fb17-4c66-b3cd-b00c9c1d440b" ascii //weight: 20
        $x_20_3 = "$9fd3cdec-0e37-4138-b834-40bd47704ff9" ascii //weight: 20
        $x_20_4 = "$255F6ED4-4FAE-420D-B41A-D94844141AE9" ascii //weight: 20
        $x_1_5 = "WindowsApp2.My.Resources" ascii //weight: 1
        $x_1_6 = "WindowsApplication1.My.Resources" ascii //weight: 1
        $x_1_7 = "ShaharMarket.Resources" ascii //weight: 1
        $x_1_8 = "Coursework.My.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_12 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_13 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_14 = "DebuggableAttribute" ascii //weight: 1
        $x_1_15 = "DebuggingModes" ascii //weight: 1
        $x_1_16 = "CreateInstance" ascii //weight: 1
        $x_1_17 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PY_2147779331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PY!MTB"
        threat_id = "2147779331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 14 72 ?? ?? ?? 70 16 8d 03 00 00 01 14 14 14 28 ?? ?? ?? 0a 14 72 ?? ?? ?? 70 18 8d 03 00 00 01 0c 08 16 72 ?? ?? ?? 70 a2 00 08 17 14 a2 00 08 14 14 14 17 28 ?? ?? ?? 0a 26 de 0f}  //weight: 2, accuracy: Low
        $x_1_2 = {06 11 05 02 11 05 91 11 04 61 08 09 91 61 b4 9c 09 03 6f ?? ?? ?? 0a 17 da fe 01 13 07 11 07 2c 04 16 0d 2b 05}  //weight: 1, accuracy: Low
        $x_1_3 = {11 04 11 05 02 11 05 91 09 61 06 07 91 61 b4 9c 07 03 6f ?? ?? ?? 0a 17 da fe 01 13 07 11 07 2c 04 16 0b 2b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_PZ_2147779335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PZ!MTB"
        threat_id = "2147779335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 09 00 00 0a 16 28 05 00 00 0a 26 28 ?? ?? ?? 06 28 07 00 00 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 06 28 07 00 00 0a 28 0e 00 00 0a 2a 14 00 28 ?? ?? ?? 06 7e ?? ?? ?? 04 7e ?? ?? ?? 04 7e ?? ?? ?? 04}  //weight: 1, accuracy: Low
        $x_1_2 = {25 0a 07 31 01 2a 02 06 28 10 00 00 0a 03 06 03 6f 0f 00 00 0a 5d 17 d6 28 10 00 00 0a da 28 11 00 00 0a 28 12 00 00 0a 28 13 00 00 0a 74 0b 00 00 01 06 17 d6 2b c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EA_2147779635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EA!MTB"
        threat_id = "2147779635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$145c0181-f8c3-49da-82e4-9aabc929fde5" ascii //weight: 20
        $x_20_2 = "$b8eacb48-b30f-4c2d-994b-030a5dfa6612" ascii //weight: 20
        $x_20_3 = "$d2099445-73d8-4209-87e1-371140b79c4f" ascii //weight: 20
        $x_5_4 = "CreateInstance" ascii //weight: 5
        $x_5_5 = "Activator" ascii //weight: 5
        $x_1_6 = "FixAPix.Resources" ascii //weight: 1
        $x_1_7 = "Image_Editor.Resources" ascii //weight: 1
        $x_1_8 = "Codewords.Resources.resources" ascii //weight: 1
        $x_1_9 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_12 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_13 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_14 = "DebuggableAttribute" ascii //weight: 1
        $x_1_15 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_EB_2147779726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EB!MTB"
        threat_id = "2147779726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$0e039d01-8c6f-4a46-a071-886e4c3d02ce" ascii //weight: 20
        $x_5_2 = "CreateInstance" ascii //weight: 5
        $x_5_3 = "Activator" ascii //weight: 5
        $x_1_4 = "GameMaker.Resources" ascii //weight: 1
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

rule Trojan_MSIL_Remcos_EC_2147779727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EC!MTB"
        threat_id = "2147779727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 16 9a 26 16 2d f9 72 8e 01 00 70 6f 68 00 00 0a 26 02 28 69 00 00 0a 0a 28 3e 00 00 0a 06 16 06 8e 69 6f 6a 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = {02 74 27 00 00 01 6f 29 00 00 0a 6f 2a 00 00 0a 6f 2b 00 00 0a 72 fe 01 00 70 72 01 00 00 70 6f 2c 00 00 0a 0a dd 6e 00 00 00 dd 06 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RF_2147779979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RF!MTB"
        threat_id = "2147779979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$ef0f6e11-2917-45a2-ae11-5e333cb795bf" ascii //weight: 1
        $x_1_2 = "DebuggableAttribute" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "lsvDados_Click" ascii //weight: 1
        $x_1_5 = "btnExcluir_Click" ascii //weight: 1
        $x_1_6 = "ContainsKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ED_2147780070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ED!MTB"
        threat_id = "2147780070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$b4c7652b-2486-44f3-8358-4bd09a03ec7c" ascii //weight: 20
        $x_5_2 = "CreateInstance" ascii //weight: 5
        $x_5_3 = "Activator" ascii //weight: 5
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "CDA.My.Resources" ascii //weight: 1
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

rule Trojan_MSIL_Remcos_EE_2147780073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EE!MTB"
        threat_id = "2147780073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Coronovirus.Coronovirus" ascii //weight: 1
        $x_1_2 = "file:///" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "Spiderman III" ascii //weight: 1
        $x_1_5 = "MovieRating" ascii //weight: 1
        $x_1_6 = "KeepAlive" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EF_2147780430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EF!MTB"
        threat_id = "2147780430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0b 07 72 86 75 00 70 28 04 00 00 06 18 14 28 07 00 00 0a 0c 08 72 9c 75 00 70 28 04 00 00 06 17 18 8d 01 00 00 01 0d 09 16 16 8c 0c 00 00 01 a2 09 28 07 00 00 0a 26 2a}  //weight: 1, accuracy: High
        $x_1_2 = {70 0a 02 6f 17 00 00 0a 17 59 0b 2b 17 06 02 07 6f 18 00 00 0a 8c 20 00 00 01 28 19 00 00 0a 0a 07 17 59 0b 07 16 2f e5 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EF_2147780430_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EF!MTB"
        threat_id = "2147780430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetType" ascii //weight: 1
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_2_5 = "asdasdas" ascii //weight: 2
        $x_2_6 = "Mones" ascii //weight: 2
        $x_1_7 = {00 62 79 74 65 73 54 6f 42 65 44 65 63 72 79 70 74 65 64 00}  //weight: 1, accuracy: High
        $x_2_8 = "exe.rtpoz/061860176029740319/910917017564740319/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EG_2147780442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EG!MTB"
        threat_id = "2147780442"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "first.Properties.Resources" ascii //weight: 20
        $x_1_2 = "Get+++Type" ascii //weight: 1
        $x_1_3 = "Ass+++embly" ascii //weight: 1
        $x_1_4 = "ToA+++rray" ascii //weight: 1
        $x_1_5 = "Loa+++d" ascii //weight: 1
        $x_1_6 = "Entr+++yPoint" ascii //weight: 1
        $x_1_7 = "In+++voke" ascii //weight: 1
        $x_1_8 = "DownloadString" ascii //weight: 1
        $x_1_9 = "Append" ascii //weight: 1
        $x_1_10 = "Replace" ascii //weight: 1
        $x_1_11 = "Concat" ascii //weight: 1
        $x_1_12 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EH_2147780583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EH!MTB"
        threat_id = "2147780583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$67e90272-ed7c-4491-9299-8d6545a62644" ascii //weight: 20
        $x_20_2 = "$8e7ce9b7-8556-4082-93a1-1ee9a099607e" ascii //weight: 20
        $x_20_3 = "$d80f6ba1-bc08-4bdf-aea5-1e4a6efb0046" ascii //weight: 20
        $x_20_4 = "$070ab36a-4ec0-4f63-8539-d0bfc3d6e2df" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "WindowsApplication1.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "Page_Restore.My.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_10 = "Singleton_Vote_Manager.Properties.Resources.resources" ascii //weight: 1
        $x_1_11 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
        $x_1_15 = "DebuggableAttribute" ascii //weight: 1
        $x_1_16 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_EJ_2147781173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EJ!MTB"
        threat_id = "2147781173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 03 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a da 0d 06 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 08 17 d6 0c 08 07 31 cd 07 00 02 08 28 ?? ?? ?? 0a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Convert" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "Concat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EK_2147781175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EK!MTB"
        threat_id = "2147781175"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 1e 5b 8d 1a 00 00 01 0b 16 0c 2b 17 07 08 06 08 1e 5a 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 08 17 58 0c 08 07 8e 69 17 59 31 e1 0b 00 28 ?? ?? ?? 0a 0a 06 6f}  //weight: 10, accuracy: Low
        $x_1_2 = "Convert" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EL_2147781386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EL!MTB"
        threat_id = "2147781386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "ExceptionDispatch.Properties.Resources" ascii //weight: 20
        $x_20_2 = "GraphicsUtility.Properties.Resources" ascii //weight: 20
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "Matrix3x3" ascii //weight: 1
        $x_1_6 = "AES_Decrypt" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
        $x_1_8 = "Convert" ascii //weight: 1
        $x_1_9 = "Concat" ascii //weight: 1
        $x_1_10 = "RotateX" ascii //weight: 1
        $x_1_11 = "RotateY" ascii //weight: 1
        $x_1_12 = "RotateZ" ascii //weight: 1
        $x_1_13 = "Flora" ascii //weight: 1
        $x_1_14 = "CreateFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 12 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_EM_2147781387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EM!MTB"
        threat_id = "2147781387"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 08 fe 01 13 07 11 07 2c 02 17 0d 03 09 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 02 11 05 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 07 08 d8 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 09 17 d6 0d 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 ac}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
        $x_1_4 = "Concat" ascii //weight: 1
        $x_1_5 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EM_2147781387_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EM!MTB"
        threat_id = "2147781387"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Csxwiq.Xgtaxbxmryvbzwbhh" wide //weight: 1
        $x_1_2 = "Aftkpyyljzyuwtkxyfsd" wide //weight: 1
        $x_1_3 = "Hxvkhdsu" wide //weight: 1
        $x_1_4 = "niaMllDroC_" ascii //weight: 1
        $x_1_5 = "margorp sihT!" ascii //weight: 1
        $x_1_6 = "blue32_c.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EN_2147782064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EN!MTB"
        threat_id = "2147782064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$72bd4aee-a426-4fac-96ea-375bfecefedd" ascii //weight: 20
        $x_20_2 = "$13971e3b-19b5-47e7-a001-239d187c9c40" ascii //weight: 20
        $x_20_3 = "$f15d04f5-5020-4926-aa68-4fe51ce3396c" ascii //weight: 20
        $x_20_4 = "$118db617-24e1-4d9c-a090-998fb436370e" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "FoxGameOfLife.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "tela_inicial.My.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_10 = "WaterBilingSystem.Main.resources" ascii //weight: 1
        $x_1_11 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
        $x_1_15 = "DebuggableAttribute" ascii //weight: 1
        $x_1_16 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_MFP_2147782174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MFP!MTB"
        threat_id = "2147782174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$af928702-be62-4b7f-ad37-151db32c847b" ascii //weight: 1
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "powershell" ascii //weight: 1
        $x_1_4 = "Encoding" ascii //weight: 1
        $x_1_5 = "GetString" ascii //weight: 1
        $x_1_6 = {57 95 02 20 09 0a 00 00 00 fa 01 33 00 16 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EO_2147782199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EO!MTB"
        threat_id = "2147782199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$114557f7-34fa-4add-9b72-e6bb6c974d5f" ascii //weight: 20
        $x_20_2 = "$3688fe2a-ac19-4d34-80a8-2168d3a52272" ascii //weight: 20
        $x_20_3 = "$005be344-cf1a-45e5-9d24-046c68c6d957" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "Activator" ascii //weight: 1
        $x_1_11 = "DebuggableAttribute" ascii //weight: 1
        $x_1_12 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_EP_2147782670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EP!MTB"
        threat_id = "2147782670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 25 16 02 28 ?? ?? ?? 06 a2 14 14 14 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 13 0c 11 07 6c 04 6c 5b 13 0d 02 11 0c 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 7d ?? ?? ?? 04 11 0d 0a 2b 25 00 00 11 07 13 06 16 13 0e 2b}  //weight: 10, accuracy: Low
        $x_1_2 = "ISectionEntry" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ES_2147783084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ES!MTB"
        threat_id = "2147783084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 16 09 16 1f 10 28 ?? ?? ?? 0a 00 11 04 16 09 1f 0f 1e 28 ?? ?? ?? 0a 00 06 09 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 13 05 02 28 ?? ?? ?? 0a 13 06 28 ?? ?? ?? 0a 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 08 13 08 de 0c}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "TripleDES_Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EQ_2147783518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EQ!MTB"
        threat_id = "2147783518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Disk Drill" ascii //weight: 1
        $x_1_2 = {63 6f 73 74 75 72 61 2e [0-15] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = ".compressed" ascii //weight: 1
        $x_1_4 = "AssemblyLoader" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "LoadStream" ascii //weight: 1
        $x_1_7 = "ConsoleApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ER_2147783519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ER!MTB"
        threat_id = "2147783519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 11 04 03 11 04 91 04 11 04 04 8e 69 5d 91 61 08 11 04 08 8e 69 5d 91 61 9c 11 04 17 d6 13 04 11 04 09 31 db}  //weight: 10, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
        $x_1_4 = "Form1_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_B_2147784197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.B!MTB"
        threat_id = "2147784197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 90 00 00 01 0a 16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f 9c 00 00 0a 1f 10 28 9d 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "51cbffca-0cb8-473c-a219-8d66052e88d4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EU_2147785192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EU!MTB"
        threat_id = "2147785192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "money.Strategies" ascii //weight: 20
        $x_20_2 = "money.exe" ascii //weight: 20
        $x_20_3 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-3] 2e 65 78 65}  //weight: 20, accuracy: Low
        $x_20_4 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-3] 2e 44 65 66 69 6e 69 74 69 6f 6e 73}  //weight: 20, accuracy: Low
        $x_20_5 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-3] 2e 41 74 74 72 69 62 75 74 65 73}  //weight: 20, accuracy: Low
        $x_1_6 = "Sandboxie Holdings, LLC" ascii //weight: 1
        $x_1_7 = "Sandboxie License Manager" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 4 of ($x_1_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_EV_2147785193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EV!MTB"
        threat_id = "2147785193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$7665c8e9-c2ed-48b5-89f6-948287d1bddd" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "AZZZZZZZZZZZZZZZX" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_EW_2147786215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EW!MTB"
        threat_id = "2147786215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$86a1b6eb-8139-47a8-b674-a5fc835ebf2d" ascii //weight: 20
        $x_20_2 = "$53d04ea0-0baa-4b63-b1a0-ab32d38967a2" ascii //weight: 20
        $x_20_3 = "$8a5f1e11-a3d4-4598-8cee-290d984904c4" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_EZ_2147787204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EZ!MTB"
        threat_id = "2147787204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 09 5a 1a 11 04 5a 58 28 ?? ?? ?? 0a 13 05 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 09 5a 1a 11 04 5a 58 11 05 28 ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 07 6f ?? ?? ?? 0a 17 59 fe 02 16 fe 01 13 06 11 06 2d ae}  //weight: 10, accuracy: Low
        $x_1_2 = "ConvertToAlphaBitmap" ascii //weight: 1
        $x_1_3 = "Manina" ascii //weight: 1
        $x_1_4 = "FromBase64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FA_2147787205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FA!MTB"
        threat_id = "2147787205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0a 2b 2b 02 7b ?? ?? ?? 04 25 6f ?? ?? ?? 0a 12 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 17 58 0a 20 e8 03 00 00 28 ?? ?? ?? 0a 06 1f 0a 32 d0}  //weight: 10, accuracy: Low
        $x_1_2 = "Sandboxie Start" ascii //weight: 1
        $x_1_3 = "ConsoleApp" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Form1_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FA_2147787205_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FA!MTB"
        threat_id = "2147787205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 [0-5] 2e 50 72 6f 70 65 72 74 69 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 39 00 31 00 2e 00 32 00 34 00 33 00 2e 00 34 00 34 00 2e 00 32 00 32 00 2f 00 [0-15] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABXY_2147787475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABXY!MTB"
        threat_id = "2147787475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 06 6f ?? ?? ?? 0a 13 07 08 11 07 28 ?? ?? ?? 0a 09 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 00 11 06 17 d6 13 06 11 06 11 05 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 16 0c 03 6f ?? ?? ?? 0a 17 da 0d 2b ?? 07 08 03 09 6f ?? ?? ?? 0a 9d 07 09 03 08 6f ?? ?? ?? 0a 9d 08 17 d6 0c 09 17 da 0d 00 08 09 fe ?? 13 ?? 11 ?? 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FB_2147789267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FB!MTB"
        threat_id = "2147789267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F_7_7_7_7_7" ascii //weight: 1
        $x_1_2 = "F_2_2_2_2_2" ascii //weight: 1
        $x_1_3 = "X_0_0_0_0_0" ascii //weight: 1
        $x_1_4 = "JustChess.Properties" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
        $x_1_8 = "Convert" ascii //weight: 1
        $x_1_9 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FD_2147789534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FD!MTB"
        threat_id = "2147789534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\kiichi\\work\\ImageResizeTest\\geo-elevation.png" ascii //weight: 1
        $x_1_2 = "AnyDesk Software GmbH" ascii //weight: 1
        $x_1_3 = "127.0.0.1:8081" ascii //weight: 1
        $x_1_4 = "localhost:8081" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "FormTest" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ECT_2147793356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ECT!MTB"
        threat_id = "2147793356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 44 58 6b 57 3c 5f 28 56 3f 63 71 4b 2e 6c 4a 3e 2d 2a 79 26 7a 76 39 70 72 66 38 62 69 59 43 46 65 4d 78 42 6d 36 5a 6e 47 33 48 34 4f 75 53 31 55 61 49 35 54 77 74 6f 41 23 52 73 21 2c 37 64 32 40 4c 5e 67 4e 68 6a 29 45 50 24 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FE_2147793984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FE!MTB"
        threat_id = "2147793984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VaZzzzzzzzzzzA" ascii //weight: 1
        $x_1_2 = "Runnnnn" ascii //weight: 1
        $x_1_3 = "123cute" ascii //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_LFGH_2147794086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.LFGH!MTB"
        threat_id = "2147794086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_InvalidOperation_HCCountOverflow" ascii //weight: 1
        $x_1_2 = "WriteByte" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "UCOMIExpando" ascii //weight: 1
        $x_1_5 = {ed 94 ad ed 93 b7 ed 94 8f ed 93 b9 ed 93 b8 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FF_2147794180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FF!MTB"
        threat_id = "2147794180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0a 0b 07 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0c 08 2c 0e 00 06 28 ?? ?? ?? 0a 0a 00 38 ?? ?? ?? 00 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 0d 09 39 ?? ?? ?? 00 00 72 ?? ?? ?? 70 06 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 04 11 04 39 ?? ?? ?? 00}  //weight: 20, accuracy: Low
        $x_1_2 = "RegEx CheatSheet" ascii //weight: 1
        $x_1_3 = "Davide Homepage" ascii //weight: 1
        $x_1_4 = "davidemauri.it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FR_2147794538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FR!MTB"
        threat_id = "2147794538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 1b 00 7e ?? ?? ?? 04 06 7e ?? ?? ?? 04 06 91 20 a5 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? ?? 04 8e 69 fe 04 0b 07 2d d7}  //weight: 1, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "AWXAWFWA2" ascii //weight: 1
        $x_1_5 = "SAFFWAF2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FR_2147794538_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FR!MTB"
        threat_id = "2147794538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DockStyle" ascii //weight: 1
        $x_1_2 = "set_ServiceName" ascii //weight: 1
        $x_1_3 = "EncodeNetbiosName" ascii //weight: 1
        $x_1_4 = "PacketMatch" ascii //weight: 1
        $x_1_5 = "ComputeHash" ascii //weight: 1
        $x_1_6 = "packetHeader" ascii //weight: 1
        $x_1_7 = "RC2CryptoServiceProvider" ascii //weight: 1
        $x_1_8 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_9 = "StringBuilder" ascii //weight: 1
        $x_1_10 = "NetworkToHostOrder" ascii //weight: 1
        $x_1_11 = "WebBrowser" ascii //weight: 1
        $x_1_12 = "BitConverter" ascii //weight: 1
        $x_1_13 = "get_EmailServer" ascii //weight: 1
        $x_1_14 = "_emailServer" ascii //weight: 1
        $x_1_15 = "GetAllNetworkInterfaces" ascii //weight: 1
        $x_1_16 = "GetPhysicalAddress" ascii //weight: 1
        $x_1_17 = "RC2Decrypt" ascii //weight: 1
        $x_1_18 = "ThreadStart" ascii //weight: 1
        $x_1_19 = "SendNetbiosQuery" ascii //weight: 1
        $x_1_20 = "VMware Virtual Ethernet Adapter" ascii //weight: 1
        $x_1_21 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FQ_2147795759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FQ!MTB"
        threat_id = "2147795759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 00}  //weight: 1, accuracy: High
        $x_1_2 = "gnirtS46esaBmorF" ascii //weight: 1
        $x_1_3 = "trevnoC.metsyS" ascii //weight: 1
        $x_1_4 = "IRnRvRoRkRe" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_MSIL_Remcos_FK_2147795884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FK!MTB"
        threat_id = "2147795884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" ascii //weight: 1
        $x_1_2 = "Start-Sleep -s" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "HttpWebRequest" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = "/store2.gofile.io/download/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FL_2147795885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FL!MTB"
        threat_id = "2147795885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$2421de9b-002b-4c64-88b6-b62d0f0d1981" ascii //weight: 1
        $x_1_2 = "FastFind.Properties.Resources" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "IsLogging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FO_2147795886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FO!MTB"
        threat_id = "2147795886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sy!stem.Refl!ection.As!sembly" ascii //weight: 1
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "ConsoleApp" ascii //weight: 1
        $x_1_4 = "Base64String" ascii //weight: 1
        $x_1_5 = "Convert" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "AnyDesk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FT_2147797344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FT!MTB"
        threat_id = "2147797344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 20 00 01 00 00 5d 13 09 38 ?? ?? ?? ?? 11 06 11 01 11 01 9e 38 ?? ?? ?? ?? 11 07 11 01 02 11 01 91 11 03 61 d2 9c 38}  //weight: 1, accuracy: Low
        $x_1_2 = "f13mdPodeN" ascii //weight: 1
        $x_1_3 = "Noworcaforab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FU_2147797346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FU!MTB"
        threat_id = "2147797346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d65e843b-be0f-4e3d-9814-ff6a00a20100" ascii //weight: 20
        $x_20_2 = "$669b474c-4b64-4adf-83b1-de9f5897796c" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_GD_2147798912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GD!MTB"
        threat_id = "2147798912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FortniteRubiconCracked" ascii //weight: 1
        $x_1_2 = "uplooder.net" ascii //weight: 1
        $x_1_3 = "wener/ gifnocpi" ascii //weight: 1
        $x_1_4 = "esaeler/ gifnocpi" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "powershell" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GG_2147798913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GG!MTB"
        threat_id = "2147798913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thedevilcoder" ascii //weight: 1
        $x_1_2 = "laxyman.000webhostapp.com" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GF_2147799399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GF!MTB"
        threat_id = "2147799399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$0bfcad74-1226-4eea-88b0-9f810ff940f5" ascii //weight: 20
        $x_20_2 = "$4c086299-8c11-4fe1-94fe-647f364ff155" ascii //weight: 20
        $x_20_3 = "$90674d83-49e4-400f-bfb6-1a372ab9d74a" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_GH_2147805217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GH!MTB"
        threat_id = "2147805217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$8fc89209-fda0-4db3-92b5-b013d74503e1" ascii //weight: 20
        $x_20_2 = "$d31a9706-6c49-4ec3-92cb-ea2a09883fe0" ascii //weight: 20
        $x_20_3 = "$e7238516-44cd-42eb-994a-7c5e3a33f0e4" ascii //weight: 20
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
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_GK_2147807320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GK!MTB"
        threat_id = "2147807320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$4a75fac5-9b36-4838-9d32-c5d07655ddf9" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_GL_2147807420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GL!MTB"
        threat_id = "2147807420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".edom SOD ni nur eb tonnac margorp sihT!" ascii //weight: 1
        $x_1_2 = "powershell" ascii //weight: 1
        $x_1_3 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "Form1_Load" ascii //weight: 1
        $x_1_6 = "coler." ascii //weight: 1
        $x_1_7 = "crsr." ascii //weight: 1
        $x_1_8 = "txet." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GM_2147807421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GM!MTB"
        threat_id = "2147807421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".edom SOD ni nur eb tonnac margorp sihT!" ascii //weight: 1
        $x_1_2 = "powershell" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "Form1_Load" ascii //weight: 1
        $x_1_6 = "coler." ascii //weight: 1
        $x_1_7 = "crsr." ascii //weight: 1
        $x_1_8 = "txet." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GN_2147807422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GN!MTB"
        threat_id = "2147807422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c27a2ae3-1cf3-473b-8f74-7d84fdeced17" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_GQ_2147807968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GQ!MTB"
        threat_id = "2147807968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c8a6f40c-fc98-41b3-b9b4-7a63f418ff12" ascii //weight: 20
        $x_20_2 = "$ae0c33af-3dcb-4ff6-bbbf-115d8c51398d" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_GR_2147808444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GR!MTB"
        threat_id = "2147808444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$f3210b37-4795-47e5-b20e-14cd1b1464b6" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_GU_2147808799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GU!MTB"
        threat_id = "2147808799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$873942b7-0216-478f-ac51-82fc4725817e" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_GW_2147808825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GW!MTB"
        threat_id = "2147808825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LibrarySystem.Properties.Resources" ascii //weight: 1
        $x_1_2 = "callmefastbrother" ascii //weight: 1
        $x_1_3 = "exe.4ewrepooc" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_STR_2147808924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.STR!MTB"
        threat_id = "2147808924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RawKeyboard" ascii //weight: 1
        $x_1_2 = "GetKeyboardState" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_4 = "ConvertToString" ascii //weight: 1
        $x_1_5 = "AsyncCallback" ascii //weight: 1
        $x_1_6 = "Rawinputheader" ascii //weight: 1
        $x_1_7 = "VirtualKeyCorrection" ascii //weight: 1
        $x_1_8 = "OpenSubKey" ascii //weight: 1
        $x_1_9 = "virtualKey" ascii //weight: 1
        $x_1_10 = "get_Assembly" ascii //weight: 1
        $x_1_11 = "CreateDecryptor" ascii //weight: 1
        $x_1_12 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_13 = "$5be6ca17-5dd1-4881-94cc-3984cc8d65e2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GY_2147809039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GY!MTB"
        threat_id = "2147809039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "car_rental.Properties.Resources" ascii //weight: 1
        $x_1_2 = "SUPRAAAAAAAA" ascii //weight: 1
        $x_1_3 = "moc.ppadrocsid.ndc//:sptth" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GZ_2147809835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GZ!MTB"
        threat_id = "2147809835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$ac893057-67de-4e7a-80df-94a12320190f" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_HA_2147809932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HA!MTB"
        threat_id = "2147809932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 [0-5] 2e 50 72 6f 70 65 72 74 69 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = "DxownxloxadDxatxxax" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "powershell" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HB_2147810552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HB!MTB"
        threat_id = "2147810552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$06bb7fe2-14fa-45d5-8d5a-ef4bf45b2814" ascii //weight: 20
        $x_20_2 = "$0f2409c3-88f0-4881-aa4d-49a41c01c985" ascii //weight: 20
        $x_20_3 = "$09c6d196-50da-43cf-bee7-f6d277ecd9c3" ascii //weight: 20
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

rule Trojan_MSIL_Remcos_HC_2147810553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HC!MTB"
        threat_id = "2147810553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$2795ab50-cdf3-4252-8e47-cfdd2c7d6960" ascii //weight: 20
        $x_20_2 = "$d736c71a-8e38-4f80-b858-2435242fb297" ascii //weight: 20
        $x_20_3 = "$e96e8c18-77e3-49cc-8f76-e264961bb5c1" ascii //weight: 20
        $x_20_4 = "$06bb7fe2-14fa-45d5-8d5a-ef4bf45b2814" ascii //weight: 20
        $x_20_5 = "$bb98ced5-194d-4608-ae40-18b013c596ef" ascii //weight: 20
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_10 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_11 = "DebuggableAttribute" ascii //weight: 1
        $x_1_12 = "DebuggingModes" ascii //weight: 1
        $x_1_13 = "FromBase64String" ascii //weight: 1
        $x_1_14 = "CreateInstance" ascii //weight: 1
        $x_1_15 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_HD_2147811190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HD!MTB"
        threat_id = "2147811190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeeHiveManagementSystem.Properties.Resources" ascii //weight: 1
        $x_1_2 = "/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii //weight: 1
        $x_1_3 = "gdgasfwq.gdgasfwq" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HE_2147811585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HE!MTB"
        threat_id = "2147811585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$9c026590-f918-4c6a-a3eb-062e58638244" ascii //weight: 20
        $x_20_2 = "$22c2b8ac-4e1a-4a7e-b4d0-c28e7a87cbc6" ascii //weight: 20
        $x_20_3 = "$f05d0dd6-a6ed-474d-a825-da0b8b029ac5" ascii //weight: 20
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
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_DOR_2147811643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.DOR!MTB"
        threat_id = "2147811643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fe 0c 02 00 20 01 00 00 00 58 20 00 00 00 00 fe 0e 02 00 45 0d 00 00 00 00 00 00 00 99 fe ff ff a8 fe ff ff ba fe ff ff cc fe ff ff db fe ff ff 05 ff ff ff 1d ff ff ff 2c ff ff ff 56 ff ff ff 8a ff ff ff 99 ff ff ff af ff ff ff dd 67 00 00 00 fe 0c 03 00 fe 0e 02 00 fe 0c 01 00 20 fe ff ff ff 3d 0a 00 00 00 20 01 00 00 00 38 04 00 00 00 fe 0c 01 00 45 02 00 00 00 00 00 00 00 7e ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_THOR_2147811644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.THOR!MTB"
        threat_id = "2147811644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 12 00 00 0a 0c 20 05 00 00 00 38 3d 00 00 00 14 0a 17 28 ?? ?? ?? 06 3a 52 00 00 00 26 20 04 00 00 00 38 25 00 00 00 1f 1c 8d 19 00 00 01 25 d0 01 00 00 04 28 ?? ?? ?? 06 0b 38 2a 00 00 00 20 03 00 00 00 fe 0e 06 00 fe 0c 06 00 45 06 00 00 00 96 ff ff ff be ff ff ff 00 00 00 00 a6 ff ff ff be ff ff ff 1a 00 00 00 38 91 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_JHOR_2147811648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.JHOR!MTB"
        threat_id = "2147811648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 7e 1c 00 00 04 29 12 00 00 11 17 7e 1d 00 00 04 29 15 00 00 11 00 14 28 25 00 00 0a 00 11 05 7e 1e 00 00 04 29 16 00 00 11 26 72 a8 02 00 70 28 ?? ?? ?? 0a 00 11 05 7e 1f 00 00 04 29 01 00 00 11 00 72 01 00 00 70 72 c8 02 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 0e 00 fe 0c 0e 00 2c 0a 72 f4 02 00 70 28 ?? ?? ?? 0a 00 00 28 ?? ?? ?? 0a 00 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_TRIMB_2147812166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.TRIMB!MTB"
        threat_id = "2147812166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GetMethod" ascii //weight: 10
        $x_10_2 = "Replace" ascii //weight: 10
        $x_10_3 = "Invoke" ascii //weight: 10
        $x_10_4 = "Reverse" ascii //weight: 10
        $x_10_5 = "ToArray" ascii //weight: 10
        $x_1_6 = "http://trietlongvinhvien.info/.tmb/" ascii //weight: 1
        $x_1_7 = "https://www.uplooder.net/img/image/40/e36bebd22260c03f3a40b6348976fa5b/WMI-Provider-Host.jpg" ascii //weight: 1
        $x_1_8 = "https://cdn.discordapp.com/attachments/932413459872747544/933098893019861042/Jdnpanki.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_GHAZ_2147812168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GHAZ!MTB"
        threat_id = "2147812168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GetMethod" ascii //weight: 10
        $x_10_2 = "Replace" ascii //weight: 10
        $x_10_3 = "Invoke" ascii //weight: 10
        $x_10_4 = "Reverse" ascii //weight: 10
        $x_10_5 = "ToArray" ascii //weight: 10
        $x_5_6 = "http://trietlongvinhvien.info//.tmb/" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_DHAZ_2147812169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.DHAZ!MTB"
        threat_id = "2147812169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0a 1e 8d 25 00 00 01 25 d0 05 00 00 04 28 ?? ?? ?? 0a 0b 73 17 00 00 0a 0c 00 73 18 00 00 0a 0d 00 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 20 80 00 00 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 3f 28 00 70 6f ?? ?? ?? 0a 13 04 11 04 07 20 e8 03 00 00 73 1d 00 00 0a 13 05 09 11 05 09 6f 1e 00 00 0a 1e 5b 6f 1f 00 00 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 25 00 00 0a 13 06 00 11 06 03 16 03 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d 11 06 2c 08 11 06 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 0a 00 de 0b 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 00 de 0b 08 2c 07 08 6f ?? ?? ?? 0a 00 dc 06 13 07 2b 00 11 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HG_2147812188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HG!MTB"
        threat_id = "2147812188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EmlakOtomasyonu.Properties.Resources" ascii //weight: 1
        $x_1_2 = "/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HH_2147812189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HH!MTB"
        threat_id = "2147812189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii //weight: 1
        $x_1_2 = "BIGBOSS" ascii //weight: 1
        $x_1_3 = "fdgfdewew" ascii //weight: 1
        $x_1_4 = "sadsadas" ascii //weight: 1
        $x_1_5 = "dsfdsf" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "DebuggingModes" ascii //weight: 1
        $x_1_8 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HI_2147812921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HI!MTB"
        threat_id = "2147812921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.kcad/tdba/171.571.34.971//:ptth" ascii //weight: 1
        $x_1_2 = "sadsadsadsadsa" ascii //weight: 1
        $x_1_3 = "fdgfdewew" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HJ_2147813130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HJ!MTB"
        threat_id = "2147813130"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NBCBCXNBNCBNCBMBNCXNCXNCNXBCNBX" ascii //weight: 1
        $x_1_2 = "DSDGSGDSS" ascii //weight: 1
        $x_1_3 = "transfer.sh/get/dXGcIL/bbddll.txt" ascii //weight: 1
        $x_1_4 = "transfer.sh/get/xwYA0C/ch.txt" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HK_2147813131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HK!MTB"
        threat_id = "2147813131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$fd79d894-8bd0-432c-aa07-bd25994d8137" ascii //weight: 1
        $x_1_2 = "Wp1.Form1.resources" ascii //weight: 1
        $x_1_3 = "telDir.Resources" ascii //weight: 1
        $x_1_4 = "notarobot" ascii //weight: 1
        $x_1_5 = "get_Red" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HM_2147813648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HM!MTB"
        threat_id = "2147813648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c2cd00f8-087d-4d95-acb2-811a27989a15" ascii //weight: 20
        $x_20_2 = "$4c53915a-1f05-4e5c-8dcf-2f4e2291b3b4" ascii //weight: 20
        $x_20_3 = "$556e9660-fa3b-4329-bc1b-c85193ec749b" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "Activator" ascii //weight: 1
        $x_1_11 = "DebuggableAttribute" ascii //weight: 1
        $x_1_12 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_FW_2147814447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FW!MTB"
        threat_id = "2147814447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bdbebaadbedcbca" ascii //weight: 1
        $x_1_2 = "DoCreateEntryFromFile" ascii //weight: 1
        $x_1_3 = "CompressionLevel" ascii //weight: 1
        $x_1_4 = "ZipArchiveMode" ascii //weight: 1
        $x_1_5 = "GetDomain" ascii //weight: 1
        $x_1_6 = "ToString" ascii //weight: 1
        $x_1_7 = "ZipFileExtensions" ascii //weight: 1
        $x_1_8 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HN_2147814451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HN!MTB"
        threat_id = "2147814451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 16 30 1b 07 17 d6 0b 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 8c ?? ?? ?? 01 6f ?? ?? ?? 0a 2b e1}  //weight: 1, accuracy: Low
        $x_1_2 = "ToInt32" ascii //weight: 1
        $x_1_3 = "GetObjectValue" ascii //weight: 1
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AM_2147815300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AM!MTB"
        threat_id = "2147815300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 02 06 91 7e 05 00 00 04 06 7e 05 00 00 04 8e 69 5d 91 61 d2 9c 06 17 58 0a 06 02 8e 69 32 df}  //weight: 2, accuracy: High
        $x_1_2 = "DecryptBytes" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KEND_2147815346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KEND!MTB"
        threat_id = "2147815346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "calina-crack.store/loader/uploads/services_Vxnwfiwc.bmp" ascii //weight: 10
        $x_10_2 = "91.243.44.142/arx-777Ofdds_Suadocfq.png" ascii //weight: 10
        $x_10_3 = "uplooder.net/img/image/48/0eda3c83452f40cb3b4ba01965a35433/Fkned.jpg" ascii //weight: 10
        $x_10_4 = "vkcgroups.com/loader/uploads/Quote_Wdmahgcs.jpg" ascii //weight: 10
        $x_10_5 = "x.rune-spectrals.com/loader/uploads/GxvGhjKm_Gxvwanla.jpg" ascii //weight: 10
        $x_10_6 = "91.243.44.142/pl-Ukxamliyg_Wqxbcfti.png" ascii //weight: 10
        $x_1_7 = "GetResponseStream" ascii //weight: 1
        $x_1_8 = "Reverse" ascii //weight: 1
        $x_1_9 = "GetType" ascii //weight: 1
        $x_1_10 = "ReadBytes" ascii //weight: 1
        $x_1_11 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_IUZ_2147815747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.IUZ!MTB"
        threat_id = "2147815747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "kotadiainc.com" ascii //weight: 10
        $x_10_2 = "philox.ddns.net" ascii //weight: 10
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "ReadBytes" ascii //weight: 1
        $x_1_7 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_OUEA_2147817273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.OUEA!MTB"
        threat_id = "2147817273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 18 58 17 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1b 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SDRA_2147817942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SDRA!MTB"
        threat_id = "2147817942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 17 58 0b 07 20 00 01 00 00 5d 0b 09 11 07 07 94 58 0d 09 20 00 01 00 00 5d 0d 11 07 07 94 13 05 11 07 07 11 07 09 94 9e 11 07 09 11 05 9e 11 07 11 07 07 94 11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 02 08 91 11 04 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 0b 11 0b 2d a0}  //weight: 1, accuracy: High
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "Kasha" ascii //weight: 1
        $x_1_5 = "Sasha" ascii //weight: 1
        $x_1_6 = "Invoke" ascii //weight: 1
        $x_1_7 = "sdafasfwqfwqfgdfsfsdgds" wide //weight: 1
        $x_1_8 = "dsfdsfe.dsfdsfe" wide //weight: 1
        $x_1_9 = "grrrr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EWB_2147817977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EWB!MTB"
        threat_id = "2147817977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 16 20 00 10 00 00 6f ?? ?? ?? 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? 0a 00 00 00 09 16 fe 02 13 05 11 05 2d d0}  //weight: 1, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "TomaszZawadzki_ZadDom2" wide //weight: 1
        $x_1_5 = "Ammit.Pearl" wide //weight: 1
        $x_1_6 = "Buta" wide //weight: 1
        $x_1_7 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAFA_2147818344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAFA!MTB"
        threat_id = "2147818344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 17 58 0b 07 20 00 01 00 00 5d 0b 09 11 07 07 94 58 0d 09 20 00 01 00 00 5d 0d 11 07 07 94 13 05 11 07 07 11 07 09 94 9e 11 07 09 11 05 9e 11 07 11 07 07 94 11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 02 08 91 11 04 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 0b 11 0b 2d a0}  //weight: 1, accuracy: High
        $x_1_2 = "Kasha" ascii //weight: 1
        $x_1_3 = "Sasha" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "makefil.makefil" wide //weight: 1
        $x_1_8 = "dsdsgsdgdsgds" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HO_2147818423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HO!MTB"
        threat_id = "2147818423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 05 04 5d 91 03 05 1f 16 5d 6f ?? ?? ?? 0a 61 0a [0-2] 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 01 00 00 0a 03 02 20 00 7a 00 00 04 28 ?? ?? ?? 06 03 04 17 58 20 00 7a 00 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 7a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_UEFA_2147819755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.UEFA!MTB"
        threat_id = "2147819755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AsSsMmB" wide //weight: 1
        $x_1_2 = "GetManifestResourceNames" wide //weight: 1
        $x_1_3 = "@System@.@Reflection@.@Assembly@" wide //weight: 1
        $x_1_4 = "@@@Method0@@@" wide //weight: 1
        $x_1_5 = "GetTypes" ascii //weight: 1
        $x_1_6 = "GetMethod" wide //weight: 1
        $x_1_7 = "Replace" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GWT_2147821484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GWT!MTB"
        threat_id = "2147821484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 8f 0d 00 00 01 25 71 0d 00 00 01 06 07 1f 10 5d 91 61 d2 81 0d 00 00 01 07 17 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GWT_2147821484_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GWT!MTB"
        threat_id = "2147821484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 14 0c 2b 2f}  //weight: 5, accuracy: Low
        $x_5_2 = {de 03 26 de 00 73 ?? 00 00 0a 72 ?? 00 00 70}  //weight: 5, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 33 00 2e 00 31 00 36 00 30 00 2e 00 33 00 32 00 2e 00 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EKFA_2147821699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EKFA!MTB"
        threat_id = "2147821699"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 06 00 fe 0c 0b 00 fe 0c 04 00 fe 0c 0b 00 fe 0c 04 00 8e 69 5d 91 fe 0c 01 00 fe 0c 0b 00 91 61 b4 9c 00 fe 0c 0b 00 20 01 00 00 00 d6 fe 0e 0b 00 fe 0c 0b 00 fe 0c 07 00 fe 02 20 00 00 00 00 fe 01 fe 0e 0c 00 fe 0c 0c 00 3a ae ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_JGM_2147822810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.JGM!MTB"
        threat_id = "2147822810"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 02 08 91 11 04 61 d2 9c 00 08 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HL_2147824207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HL!MTB"
        threat_id = "2147824207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 02 11 07 91 08 11 07 08 8e 69 5d 91 61 09 61 d2 6f ?? ?? ?? 0a 00 00 11 07 17 58 13 07 11 07 02 8e 69 fe 04 13 08 11 08 2d d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_YVR_2147824708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.YVR!MTB"
        threat_id = "2147824708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 18 5b 1f 10 59 0d 08 1f 20 2f 16 06 08 18 5b 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 2b 1b 07 09 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 06 09 06 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? ?? ?? 0a 32 b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEC_2147824717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEC!MTB"
        threat_id = "2147824717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 73 16 00 00 0a 0c 00 07 08 6f 19 00 00 0a 00 08 6f 1b 00 00 0a 0d de 16}  //weight: 1, accuracy: High
        $x_1_2 = "Vsvaqvazwvtgnixo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEA_2147825938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEA!MTB"
        threat_id = "2147825938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MandalMagic" wide //weight: 1
        $x_1_2 = "$$NoBodyCanGetIt$$" wide //weight: 1
        $x_1_3 = "$$MLKjclkdsjfklsdfkghfdkhgfhmjlyil$$" wide //weight: 1
        $x_1_4 = "ASAMethod0ASA" wide //weight: 1
        $x_1_5 = "vMvevtvhvovdv0v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZJXF_2147826120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZJXF!MTB"
        threat_id = "2147826120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 06 00 00 04 73 48 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 07 00 00 1b 0a 06 28 14 00 00 06 0b 07 72 ?? ?? ?? 70 28 15 00 00 06 74 93 00 00 01 6f 4a 00 00 0a 1f 0b 9a 80 05 00 00 04 23 20 6d 4e eb 57 0a 18 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ENM_2147826134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ENM!MTB"
        threat_id = "2147826134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 03 11 07 91 08 11 07 08 8e 69 5d 91 61 09 61 d2 6f ?? ?? ?? 0a 00 00 11 07 17 58 13 07 11 07 03 8e 69 fe 04 13 08 11 08 2d d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEF_2147827661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEF!MTB"
        threat_id = "2147827661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 06 00 00 06 25 6f 07 00 00 06 25 6f 08 00 00 06 25 6f 09 00 00 06 2b 01 2a 6f 0a 00 00 06 2b f8}  //weight: 5, accuracy: High
        $x_4_2 = {2b c9 02 2b cd 28 01 00 00 06 2b cd 28 1b 00 00 0a 2b c8}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEF_2147827661_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEF!MTB"
        threat_id = "2147827661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 04 03 8e 69 28 ?? 00 00 06 d6 13 04 11 04 04 5f 13 05 09 03 8e 69 28 ?? 00 00 06 13 06 03 11 06 91 13 07 11 07 11 05}  //weight: 1, accuracy: Low
        $x_1_2 = "AsSsMmB" wide //weight: 1
        $x_1_3 = "@System@.@Reflection@.@Assembly@" wide //weight: 1
        $x_1_4 = "@@@Method0@@@" wide //weight: 1
        $x_1_5 = "Invoke" wide //weight: 1
        $x_1_6 = "%c0jm0ds" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MD_2147828053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MD!MTB"
        threat_id = "2147828053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 09 16 20 00 10 00 00 6f ?? ?? ?? 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f ?? ?? ?? 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb}  //weight: 10, accuracy: Low
        $x_1_2 = {57 3f a2 1f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 7a 00 00 00 1a}  //weight: 1, accuracy: High
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "GetTypes" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MAO_2147828105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MAO!MTB"
        threat_id = "2147828105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 e0 95 58 20 ff 00 00 00 5f e0 95 61 28 ?? ?? ?? 0a 9c 11 06 17 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NE_2147828112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NE!MTB"
        threat_id = "2147828112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 02 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 58 0c 11 04 18 58 13 04 11 04 1f 0f 32 e3}  //weight: 1, accuracy: Low
        $x_1_2 = "Qreoknrerxpbigohihascd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FWC_2147828295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FWC!MTB"
        threat_id = "2147828295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 07 09 07 8e 69 5d 91 06 09 91 61 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEH_2147828315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEH!MTB"
        threat_id = "2147828315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 07 73 0d 01 00 06 a2 06 07 9a 03 07 a3 22 00 00 02 6f 04 01 00 06 00 06 07 9a 02 6f 06 01 00 06}  //weight: 1, accuracy: High
        $x_1_2 = "RS55Q74D7H7GH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEI_2147828547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEI!MTB"
        threat_id = "2147828547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 07 8e 69 5d 91 06 09 91 61 d2 6f ?? 00 00 0a 09 13 04 11 04 17 58 0d 09 06 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NWM_2147828638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NWM!MTB"
        threat_id = "2147828638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d4}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "SAFASFASFSFSAFSFSA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FWM_2147828667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FWM!MTB"
        threat_id = "2147828667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEJ_2147828750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEJ!MTB"
        threat_id = "2147828750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 9a 2b 0f 2b 14 2b 19 2a 02 2b ed 6f ?? 00 00 0a 2b ed 28 ?? 00 00 2b 2b ea 6f ?? 00 00 0a 2b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEK_2147828929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEK!MTB"
        threat_id = "2147828929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7968B09EBE12EBB" ascii //weight: 1
        $x_1_2 = "9E74BDE4C273A1C" ascii //weight: 1
        $x_1_3 = "XG5V44QZHEORH7172G4UR8" wide //weight: 1
        $x_1_4 = "Poison.Train" wide //weight: 1
        $x_1_5 = "EdDG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEE_2147829228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEE!MTB"
        threat_id = "2147829228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 18 02 72 01 00 00 70 28 04 00 00 06 0c 08 16 08 8e 69 28 03 00 00 0a 2b 07 28 04 00 00 0a 2b e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABN_2147829257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABN!MTB"
        threat_id = "2147829257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {57 15 a2 09 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a3 00 00 00 14 00 00 00 a6 00 00 00 71 01 00 00 cf 00 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "get_lnkPassword" ascii //weight: 1
        $x_1_3 = "get_WebServices" ascii //weight: 1
        $x_1_4 = "User ID or Password does not match" wide //weight: 1
        $x_1_5 = "grpLogin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_XXM_2147829489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.XXM!MTB"
        threat_id = "2147829489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 09 08 09 08 8e 69 5d 91 07 09 91 61 d2 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MF_2147829585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MF!MTB"
        threat_id = "2147829585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 5f 13 08 07 09 11 08 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MF_2147829585_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MF!MTB"
        threat_id = "2147829585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 1d a2 09 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 8c 00 00 00 11 00 00 00 48 00 00 00 a9 00 00 00 58}  //weight: 10, accuracy: High
        $x_1_2 = "$ae07f19f-a079-477e-b86b-e6c86f3f83d3" ascii //weight: 1
        $x_1_3 = "get_Assembly" ascii //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "Create__Instance__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABF_2147829608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABF!MTB"
        threat_id = "2147829608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 02 03 73 ?? ?? ?? 0a 8c ?? ?? ?? 01 13 05 2b 00 11 05 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_TCGA_2147829692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.TCGA!MTB"
        threat_id = "2147829692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "Ilop" wide //weight: 1
        $x_1_3 = "ComputeHash" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GAN_2147829931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GAN!MTB"
        threat_id = "2147829931"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 33 2b 34 72 ?? ?? ?? 70 2b 34 2b 39 2b 3e 2b 3f 2b 40 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 02 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_OZM_2147829943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.OZM!MTB"
        threat_id = "2147829943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 07 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 06 08 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 02 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RBN_2147829944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RBN!MTB"
        threat_id = "2147829944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 06 08 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 02 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PDZF_2147829945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PDZF!MTB"
        threat_id = "2147829945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 18 06 08 2b 09 06 18 6f ?? ?? ?? 0a 2b 07 6f ?? ?? ?? 0a 2b f0 02 0d 2b 03 26 2b e5 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_XBN_2147829983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.XBN!MTB"
        threat_id = "2147829983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d4}  //weight: 2, accuracy: Low
        $x_1_2 = "drivenbyr" wide //weight: 1
        $x_1_3 = "heys" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MG_2147830009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MG!MTB"
        threat_id = "2147830009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 b7 b6 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 fb 00 00 00 4c 00 00 00 98 00 00 00 d5}  //weight: 10, accuracy: High
        $x_1_2 = "Cortez.Properties.Resources" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MI_2147830010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MI!MTB"
        threat_id = "2147830010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Star_Wars_The_Empire_Strikes_Back_icon" ascii //weight: 1
        $x_1_2 = "XCCVV" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MJ_2147830011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MJ!MTB"
        threat_id = "2147830011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 9f b6 2b 09 1e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5a 01 00 00 95 01 00 00 ed 05 00 00 6f}  //weight: 10, accuracy: High
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "WebResponse" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MK_2147830012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MK!MTB"
        threat_id = "2147830012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 1d a2 1f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 c3 00 00 00 14 00 00 00 f3 00 00 00 89}  //weight: 10, accuracy: High
        $x_1_2 = "$b8ca1f97-cc21-419e-8c6b-51e643c0e997" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ADIV_2147830108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ADIV!MTB"
        threat_id = "2147830108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 16 00 00 04 06 7e 16 00 00 04 06 91 20 44 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 16 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_COR_2147830189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.COR!MTB"
        threat_id = "2147830189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 2b 8b 00 00 8d 11 00 00 01 25 d0 04 00 00 04 28 ?? ?? ?? 0a 0a 20 73 66 01 00 8d 11 00 00 01 25 d0 05 00 00 04 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 06 0c 06 28 ?? ?? ?? 06 0d 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_JCN_2147830193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.JCN!MTB"
        threat_id = "2147830193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Pulbicsfdfsafsafsafsafsafas" ascii //weight: 1
        $x_1_3 = "publs" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_IDN_2147830259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.IDN!MTB"
        threat_id = "2147830259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "DSAFSAFSAFSFSAFSAFSAFSFSA" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_LFGA_2147830276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.LFGA!MTB"
        threat_id = "2147830276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 d1 26 00 70 28 ?? ?? ?? 06 0b 73 0e 02 00 0a 0c 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59}  //weight: 2, accuracy: Low
        $x_1_2 = "Aintac" wide //weight: 1
        $x_1_3 = "545BGGP79TP5ND87G5XQ88" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RED_2147830396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RED!MTB"
        threat_id = "2147830396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 0c 00 00 28 ?? ?? ?? 0a de 03 26 de 00 00 73 ?? ?? ?? 0a 0a 02 73 ?? ?? ?? 0a 0b 06 07 6f ?? ?? ?? 0a 0c de 0d 06 2c 06 06 6f ?? ?? ?? 0a dc 26 de db}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ML_2147830399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ML!MTB"
        threat_id = "2147830399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 95 02 20 09 0a 00 00 00 00 00 00 00 00 00 00 01 00 00 00 39 00 00 00 08 00 00 00 87 00 00 00 1b}  //weight: 10, accuracy: High
        $x_1_2 = "$04b65cb8-f24b-4de9-8f91-d57c0e2633a3" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "WebResponse" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MM_2147830400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MM!MTB"
        threat_id = "2147830400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 00 10 00 00 8d ?? ?? ?? 01 0d 38 0a 00 00 00 07 09 16 11 04 6f ?? ?? ?? 0a 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 30 e5}  //weight: 10, accuracy: Low
        $x_1_2 = {57 95 02 28 09 02 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 31 00 00 00 06 00 00 00 01 00 00 00 09}  //weight: 1, accuracy: High
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "WebResponse" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MN_2147830401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MN!MTB"
        threat_id = "2147830401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 95 02 20 09 0a 00 00 00 00 00 00 00 00 00 00 01 00 00 00 36 00 00 00 08 00 00 00 73 00 00 00 25}  //weight: 10, accuracy: High
        $x_1_2 = "$d0266957-c1c8-40a6-a181-23c28606f23f" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "HttpWebResponse" ascii //weight: 1
        $x_1_5 = "HttpWebRequest" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MO_2147830403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MO!MTB"
        threat_id = "2147830403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 9f a2 29 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 d6 00 00 00 50 00 00 00 35 01}  //weight: 10, accuracy: High
        $x_1_2 = "$535d1cef-ab16-4669-af87-45443da3fb39" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "AppDomain" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_IGGA_2147830409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.IGGA!MTB"
        threat_id = "2147830409"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 7c 07 00 70 6f ?? ?? ?? 0a 74 17 00 00 1b 0a 17 72 88 07 00 70 28 ?? ?? ?? 06 0b 73 fd 00 00 0a 0c 08 1f 10 07 28 ?? ?? ?? 06 74 17 00 00 1b 6f ?? ?? ?? 0a 00 08 1f 10 07 28 ?? ?? ?? 06 74 17 00 00 1b 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59}  //weight: 2, accuracy: Low
        $x_1_2 = "57H3FNPC54JHXFFF8DC347" wide //weight: 1
        $x_1_3 = "Qauli" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_DED_2147830437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.DED!MTB"
        threat_id = "2147830437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 21 06 08 2b 09 06 18 6f ?? ?? ?? 0a 2b 07 6f ?? ?? ?? 0a 2b f0 72}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MP_2147830632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MP!MTB"
        threat_id = "2147830632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 00 10 00 00 8d ?? ?? ?? 01 0d 2b 0a 07 09 16 11 04 6f ?? ?? ?? 0a 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 30 e5}  //weight: 10, accuracy: Low
        $x_1_2 = {57 95 02 28 09 0e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 3c 00 00 00 0b 00 00 00 0f 00 00 00 16}  //weight: 1, accuracy: High
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "WebResponse" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MQ_2147830633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MQ!MTB"
        threat_id = "2147830633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 11 0b 75 42 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MQ_2147830633_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MQ!MTB"
        threat_id = "2147830633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 95 02 20 09 02 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 28 00 00 00 07 00 00 00 01 00 00 00 0a}  //weight: 10, accuracy: High
        $x_1_2 = "$899c24c4-2b60-4aa5-8309-72bd3d3d10d3" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MYH_2147830635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MYH!MTB"
        threat_id = "2147830635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 1e 00 00 04 72 e9 04 00 70 72 ed 04 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 06 14 72 f3 04 00 70 17 8d 17 00 00 01 25 16 07}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "SSL2_Aim_Assist" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_REN_2147830638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.REN!MTB"
        threat_id = "2147830638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 16 39 9b 00 00 00 26 26 38 9e 00 00 00 20 80 00 00 00 38 9a 00 00 00 38 9f 00 00 00 72}  //weight: 1, accuracy: High
        $x_1_2 = {06 20 e8 03 00 00 73 ?? ?? ?? 0a 0d 08 09 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 09 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 17 6f ?? ?? ?? 0a 07 08 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SPQE_2147830930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SPQE!MTB"
        threat_id = "2147830930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 16 93 17 58 d1 9d 08 17 58 d1 0c 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FJGA_2147831139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FJGA!MTB"
        threat_id = "2147831139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_XDN_2147831288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.XDN!MTB"
        threat_id = "2147831288"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 20 80 00 00 00 2b 49 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 7e 02 00 00 04 20 e8 03 00 00 73 18 00 00 0a 0c 07 08 07 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FKGA_2147831298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FKGA!MTB"
        threat_id = "2147831298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8}  //weight: 2, accuracy: Low
        $x_1_2 = "BattleshipLiteLibrary" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AU_2147831374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AU!MTB"
        threat_id = "2147831374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "172.245.142.35" wide //weight: 5
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "GetMethod" ascii //weight: 1
        $x_1_7 = "Names/Name" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EJN_2147831543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EJN!MTB"
        threat_id = "2147831543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 c8 00 00 00 59 1f 64 59 1f 1e 58 20 ?? ?? ?? 00 59 13 04 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 06 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RS_2147831633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RS!MTB"
        threat_id = "2147831633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 8f 00 00 00 38 90 00 00 00 02 8e 69 5d 7e 6d 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 d6 00 00 06 02 08 17 58 02 8e 69 5d 91}  //weight: 1, accuracy: High
        $x_1_2 = {59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 ac 0f 00 02 8e 69 17 59 28 01 00 00 2b 02 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FJN_2147831836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FJN!MTB"
        threat_id = "2147831836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 e8 03 00 00 73 29 00 00 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "leees" wide //weight: 1
        $x_1_4 = "ASDASfsafasfsafasfsafsafasfas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RJN_2147831837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RJN!MTB"
        threat_id = "2147831837"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 80 00 00 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 13 04 03 07 20 e8 03 00 00 73 ?? ?? ?? 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "sdgsd" wide //weight: 1
        $x_1_4 = "ASDASfsafasfsafasfsafsafasfas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SJN_2147831838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SJN!MTB"
        threat_id = "2147831838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 5d 91 02 11 03 91 61 d2 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_CZM_2147831840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.CZM!MTB"
        threat_id = "2147831840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 8e 2c 39 06 2c 36 06 28 ?? ?? ?? 0a 0b 16 0c 28 ?? ?? ?? 0a 0d 2b 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ACLN_2147832139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ACLN!MTB"
        threat_id = "2147832139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 6f ?? ?? ?? 0a 00 09 20 80 00 00 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 13 04 03 07 20 e8 03 00 00 73 27 00 00 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "heys.heys" wide //weight: 1
        $x_1_4 = "HEYSFSAW" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHP_2147832991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHP!MTB"
        threat_id = "2147832991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 20 06 6f ?? ?? ?? 0a 13 06 11 04 08 02 11 06 18 5a 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMQ_2147832995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMQ!MTB"
        threat_id = "2147832995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Prototype" wide //weight: 1
        $x_1_3 = "UYR0010453" ascii //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AH_2147833237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AH!MTB"
        threat_id = "2147833237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 16 0c 2b 16 07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 02 8e 69 32}  //weight: 2, accuracy: Low
        $x_2_2 = "80.66.75.123/Jicot_Afokgyay.png" wide //weight: 2
        $x_1_3 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AGT_2147833492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AGT!MTB"
        threat_id = "2147833492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 08 8e 69 17 da 0d 09 13 04 2b 16 07 08 11 04 93 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 15 d6 13 04 11 04 16 2f e5}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Advanced_Html_Editor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AIEC_2147833828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AIEC!MTB"
        threat_id = "2147833828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 4e 00 16 13 04 2b 34 00 08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28}  //weight: 2, accuracy: Low
        $x_1_2 = "MatchingGame" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ACKB_2147833951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ACKB!MTB"
        threat_id = "2147833951"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 29 06 0c 16 0d 08 12 03 28 ?? ?? ?? 0a 06 03 07 28 ?? ?? ?? 06 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AIGF_2147834289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AIGF!MTB"
        threat_id = "2147834289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 17 13 04 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Chess" wide //weight: 1
        $x_1_3 = "CargoWise.White" wide //weight: 1
        $x_1_4 = "Sanford101" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AIGJ_2147834290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AIGJ!MTB"
        threat_id = "2147834290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 16 0c 2b 4e 00 16 0d 2b 36 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 17 13 04 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "Collector" wide //weight: 1
        $x_1_3 = "Sanford101" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AIGH_2147834291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AIGH!MTB"
        threat_id = "2147834291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 36 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 17 13 04 00 28 ?? ?? ?? 06 d2 06 28}  //weight: 2, accuracy: Low
        $x_1_2 = "JarrettVance.Updater" wide //weight: 1
        $x_1_3 = "CargoWise.White" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AGVY_2147834292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AGVY!MTB"
        threat_id = "2147834292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "WeekTimeProgram" wide //weight: 1
        $x_1_3 = "CargoWise.White" wide //weight: 1
        $x_1_4 = "GetPixel" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AREC_2147834293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AREC!MTB"
        threat_id = "2147834293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 36 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 17 13 04 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "AttenuatorTest" wide //weight: 1
        $x_1_3 = "intel22" wide //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEAA_2147834396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEAA!MTB"
        threat_id = "2147834396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 05 2b 0a 2b 0f 2a 28 ?? 00 00 0a 2b f4 28 ?? 00 00 06 2b ef 6f ?? 00 00 0a 2b ea}  //weight: 5, accuracy: Low
        $x_5_2 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 02 2b f3 03 2b f2 6f ?? 00 00 0a 2b ee 28 ?? 00 00 0a 2b eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MR_2147834414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MR!MTB"
        threat_id = "2147834414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 13 05 16 13 06 11 05 12 06 28 ?? ?? ?? 0a 07 11 04 18 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 13 07 08 11 04 11 07 6f ?? ?? ?? 0a de 0c 11 06 2c 07 11 05 28 ?? ?? ?? 0a dc 11 04 18 58 13 04 11 04 07 6f ?? ?? ?? 0a 32 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {57 95 02 28 09 0a 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2b 00 00 00 06 00 00 00 04 00 00 00 0a 00 00 00 01 00 00 00 2c 00 00 00 0f 00 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AIM_2147834471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AIM!MTB"
        threat_id = "2147834471"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0c 2b 30 07 0d 16 13 04 09 12 04 28 ?? ?? ?? 0a 06 08 28 ?? ?? ?? 06 13 05 07 08 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AGW_2147834661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AGW!MTB"
        threat_id = "2147834661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 00 07 15 58}  //weight: 2, accuracy: Low
        $x_1_2 = "DriveDetector" wide //weight: 1
        $x_1_3 = "G4D54C7D48A57E47Y87HB4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABCA_2147834855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABCA!MTB"
        threat_id = "2147834855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 8e 69 5d 91 02 08 91 61 d2 6f 19 00 00 0a 08 17 58 0c 08 02 8e 69 32 e1 07 2a}  //weight: 1, accuracy: High
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHBC_2147835049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHBC!MTB"
        threat_id = "2147835049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 6e 02 07 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "D774Z478V4S7392GGBH54G" wide //weight: 1
        $x_1_3 = "PromoCore" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AOBD_2147835195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AOBD!MTB"
        threat_id = "2147835195"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 08 11 04 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 11 04 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 13 05 07 08}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AFSQ_2147835503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AFSQ!MTB"
        threat_id = "2147835503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 02 00 00 04 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0a 2b 00 06}  //weight: 2, accuracy: Low
        $x_1_2 = "Helper_Classes" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AOBV_2147835504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AOBV!MTB"
        threat_id = "2147835504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 07 06 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AEOQ_2147835505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AEOQ!MTB"
        threat_id = "2147835505"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 06 08 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AGCM_2147835609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AGCM!MTB"
        threat_id = "2147835609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07}  //weight: 2, accuracy: Low
        $x_1_2 = "RiichiSharp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NZA_2147835625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NZA!MTB"
        threat_id = "2147835625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06}  //weight: 1, accuracy: Low
        $x_1_2 = {62 00 cc 06 59 00 46 06 86 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NZA_2147835625_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NZA!MTB"
        threat_id = "2147835625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 07 00 fe 0c 28 00 20 05 00 00 00 9c fe 0c 1e 00 fe 0c 28 00 7e ?? ?? ?? 04 fe 0c 0f 00 fe 0c 03 00 58 4a 97 29 0d 00 00 11 a2 fe 0c 28 00 20 01 00 00 00 58 fe 0e 28 00 fe 0c 0f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "bd91-c8a5b7c8906f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABDI_2147835716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABDI!MTB"
        threat_id = "2147835716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c}  //weight: 4, accuracy: Low
        $x_1_2 = "EcoBoost" wide //weight: 1
        $x_1_3 = "745445BJ5CHO8980FGGAZ7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEAB_2147836089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEAB!MTB"
        threat_id = "2147836089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 8e 69 5d 91 02 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 02 8e 69 32 e1 07 2a}  //weight: 10, accuracy: Low
        $x_5_2 = {2b 03 2b 08 2a 28 ?? 00 00 06 2b f6 28 ?? 00 00 0a 2b f1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AGRT_2147836105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AGRT!MTB"
        threat_id = "2147836105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 8e 69 5d 91 7e ?? ?? ?? 04 11 01 91 61 d2 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHFJ_2147836108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHFJ!MTB"
        threat_id = "2147836108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 08 2b 1d 07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 8c 54 00 00 01 6f ?? ?? ?? 0a 26 11 08 17 58 13 08 11 08}  //weight: 2, accuracy: Low
        $x_1_2 = "Mill" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHFL_2147836109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHFL!MTB"
        threat_id = "2147836109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 8c 59 00 00 01 6f ?? ?? ?? 0a 26 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09}  //weight: 2, accuracy: Low
        $x_1_2 = "GUI_Demo1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AJG_2147836317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AJG!MTB"
        threat_id = "2147836317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 13 04 2b 1b 08 11 04 9a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 33 04 16 0a 2b 0d 11 04 17 58 13 04 11 04 08 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHHE_2147836357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHHE!MTB"
        threat_id = "2147836357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 08 2b 15 07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "CurrencyConverter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHHM_2147836369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHHM!MTB"
        threat_id = "2147836369"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09}  //weight: 2, accuracy: Low
        $x_1_2 = "DashBoard" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AIMA_2147836502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AIMA!MTB"
        threat_id = "2147836502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 08 a2 25 0d 14 14 17 8d 5e 00 00 01 25 16 17 9c 25 13 04 28 ?? ?? ?? 0a 11 04 16 91}  //weight: 2, accuracy: Low
        $x_1_2 = "FlyPushBooks" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AEKW_2147836504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AEKW!MTB"
        threat_id = "2147836504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ?? ?? ?? 06 02 07 17 58 02 8e 69 5d 91}  //weight: 2, accuracy: Low
        $x_1_2 = "Landry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHTI_2147836505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHTI!MTB"
        threat_id = "2147836505"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 17 28}  //weight: 2, accuracy: Low
        $x_1_2 = "LoLNotes" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NZK_2147836916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NZK!MTB"
        threat_id = "2147836916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 8e 69 5d 91 06 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 06 8e 69 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NZT_2147837414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NZT!MTB"
        threat_id = "2147837414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 13 06 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 07 11 07 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a de}  //weight: 1, accuracy: Low
        $x_3_2 = "Wwihlaazshjcxlari.Xhbviussamolczboby" wide //weight: 3
        $x_3_3 = "Amxewoewiotdsroxemikcxdo.Rzopglyn" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Remcos_ABGM_2147837954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABGM!MTB"
        threat_id = "2147837954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 09 07 09 1e d8 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 09 17 d6 0d 09 11 04 31 e4}  //weight: 2, accuracy: Low
        $x_2_2 = {13 07 d0 34 ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 17 8d ?? ?? ?? 01 13 0c 11 0c 16 11 07 a2 11 0c 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 13 06}  //weight: 2, accuracy: Low
        $x_1_3 = "b62c3.resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABGX_2147837960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABGX!MTB"
        threat_id = "2147837960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 11 0a 75 09 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 09 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 40 00 00 0a 26 1f 0f 13 0e 38 39 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "214da9226666a1.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 16 13 04 38 24 00 00 00 09 11 04 a3 02 00 00 01 13 05 08 11 05 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 11 01 02 11 01 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 08 06 08 8e 69 5d 91 09 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 09 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 04 18 5b 07 11 04 18 6f 17 00 00 0a 1f 10 28 18 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1d 5f 58 13 04 2b 15 02 7b 69 00 00 04 18 1f 0a 28 ?? ?? ?? 06 11 04 1f 0a 59 13 04 11 04 16 30 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 06 1a 58 4a 04 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? ?? 06 04 06 1a 58 4a 1b 58 19 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 2d 06 d0 38 00 00 06 26 72 5d 00 00 70 0a 06 28 73 00 00 0a 25 26 0b 28 74 00 00 0a 25 26 07 16 07 8e 69 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 13 04 02 28 01 00 00 0a 13 05 28 09 00 00 0a 11 04 11 05 16 11 05 8e 69 6f 0f 00 00 0a 6f 10 00 00 0a 0c 08 13 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 51 00 00 04 06 7e 51 00 00 04 06 91 20 89 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 51 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 0b 07 28 31 00 00 0a 0c 08 16 08 8e 69 28 32 00 00 0a 08 0d de 1b}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 3d 00 00 70 a2 25 17 7e 1d 00 00 0a a2 25 18 06 72 7d 00 00 70 6f}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? ?? 06 02 06 1a 58 4a 1b 58 19 59 17 59 02 8e 69 5d 91 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 13 04 2b 1e 09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 13 05 11 05 17 58 13 04 11 04 08 8e 69 32 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 21 06 07 9a 0c 08 72 ?? ?? ?? 70 20 00 01 00 00 14 14 14 6f ?? ?? ?? 0a 26 de 03 26 de 00 07 17 58 0b 07 06 8e 69 32 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 04 06 11 04 8e 69 5d 91 09 06 91 61 d2 6f ?? ?? ?? 0a 06 0c 08 17 58 0a 06 09 8e 69 32 dc 11 05 6f ?? ?? ?? 0a 13 06 16 2d ee}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1c 2d 1d 26 07 28 ?? ?? ?? 0a 0c 08 16 08 8e 69 28 ?? ?? ?? 0a 08 0d de 25}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 08 72 95 49 00 70 28 ?? ?? ?? 0a 72 b3 49 00 70 20 00 01 00 00 14 14 18 8d 10 00 00 01 25 16 06 11 08 9a a2 25 17 1f 10}  //weight: 2, accuracy: Low
        $x_1_2 = "Peli" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 16 13 04 2b 3b 09 17 8d ?? ?? ?? 01 25 16 08 17 8d ?? ?? ?? 01 25 16 11 04 8c ?? ?? ?? 01 a2 14 28}  //weight: 2, accuracy: Low
        $x_1_2 = "PokemonApp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 09 17 6f ?? ?? ?? 06 08 6f ?? ?? ?? 06 09 6f ?? ?? ?? 0a 72 29 00 00 70 28 ?? ?? ?? 06 08 6f ?? ?? ?? 06 6f ?? ?? ?? 06 73 2e 04 00 06 1f 16 73 95 06 00 06 13 04 09 6f ?? ?? ?? 06 11 04 6f ?? ?? ?? 0a 16 13 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 15 2b 28 00 11 13 11 15 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 17 11 14 11 17 6f ?? ?? ?? 0a 00 11 15 18 58 13 15 00 11 15 11 13 6f ?? ?? ?? 0a fe 04 13 18 11 18 2d c7}  //weight: 2, accuracy: Low
        $x_1_2 = "GUIGame" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 2b 19 00 02 7b af 00 00 04 06 8f 79 00 00 01 25 47 03 58 d2 52 00 06 17 58 d2 0a 06 1f 0a fe 04 0b 07 2d de}  //weight: 2, accuracy: High
        $x_1_2 = "ecnatsnIetaerC" wide //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
        $x_1_4 = "osukps" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {91 13 11 11 11 11 0a 61 11 0e 59 20 00 02 00 00 58 13 12 11 12 20 00 01 00 00 5d 20 00 04 00 00 58 13 13 16 13 1b 2b}  //weight: 2, accuracy: High
        $x_2_2 = {20 00 02 00 00 5d 13 14 11 14 20 00 01 00 00 59 20 00 04 00 00 58 13}  //weight: 2, accuracy: High
        $x_1_3 = "55ZJG5TE7CJ865EHZGCE40" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 09 28 ?? ?? ?? 06 13 05 18 8d ?? ?? ?? 01 13 06 11 06 16 72 ?? ?? ?? 70 a2 11 06 17 11 05 28 ?? ?? ?? 0a a2 11 06 13 07 11 04 28}  //weight: 2, accuracy: Low
        $x_1_2 = "/st 00:00 /du 9999:59 /sc once /ri 60 /f" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 05 72 37 e0 1c 70 11 05 6f 12 00 00 0a 28 01 00 00 0a 28 13 00 00 0a 72 01 00 00 70 13 04 dd 00 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "FOqrLWzAmTNeciR.FOqrLWzAmTNeciR" wide //weight: 1
        $x_1_3 = "sMMMcTSKDxERLwb" wide //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetBytes" ascii //weight: 1
        $x_1_2 = "RobX.Interface.Article" wide //weight: 1
        $x_1_3 = "Exit" wide //weight: 1
        $x_1_4 = "857H487ZSH97Q4HZB874CC" wide //weight: 1
        $x_1_5 = "RobX Hardware Interface" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 2b 67 00 28 12 00 00 0a 20 00 9c 4d 00 8d 0d 00 00 01 25 d0 02 00 00 04 28 13 00 00 0a 6f 14 00 00 0a 0b 07 6f 15 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "Gudqpbpslstaktr.Khsvfcllopzctfpwolblhzl" wide //weight: 1
        $x_1_3 = "Oncqugbowevpyuadqvecpt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_26
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "This tool is used as a simple scorboard for the Yahtzee dice game" wide //weight: 2
        $x_2_2 = "Yathzee" wide //weight: 2
        $x_2_3 = "Yahtzee Scorboard" wide //weight: 2
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_27
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 1d 13 05 06 28 ?? ?? ?? 0a 7e 09 00 00 04 15 16 28 ?? ?? ?? 0a 18 9a 72 15 01 00 70 16 28 ?? ?? ?? 0a 16 33 3b 1e 13 05 07 28 ?? ?? ?? 0a 2d 2e 1f 09 13 05 07 06 28 ?? ?? ?? 0a 7e 09 00 00 04 15 16 28 ?? ?? ?? 0a 16 9a 28}  //weight: 2, accuracy: Low
        $x_1_2 = "svchost.exe||'^'||True||'^'||False" wide //weight: 1
        $x_1_3 = "spec.exe||'^'||True||'^'||False" wide //weight: 1
        $x_1_4 = "Build.exe||'^'||True||'^'||False" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AR_2147838078_28
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AR!MTB"
        threat_id = "2147838078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IiAvc3QgMDA6MDAgL2R1IDk5OTk6NTkgL3NjIG9uY2UgL3JpIDMgL2Y=" wide //weight: 1
        $x_1_2 = "L0Mgc2NodGFza3MgL2NyZWF0ZSAvdG4gX" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "PolarisObfuscationSoftware" wide //weight: 1
        $x_1_5 = "PolarisCopyRight" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABGK_2147838440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABGK!MTB"
        threat_id = "2147838440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f 1e 00 00 0a 08 17 58 0c 08 02 8e 69 32 e3 07 2a}  //weight: 2, accuracy: High
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDE_2147838979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDE!MTB"
        threat_id = "2147838979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Matrix Architectural" wide //weight: 1
        $x_1_2 = "Demographer" wide //weight: 1
        $x_2_3 = {11 07 11 05 25 17 58 13 05 11 0b 1f 18 64 d2 9c 08 11 0a 8f 37 00 00 01 25 4b 11 0b 61 54}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABJV_2147839041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABJV!MTB"
        threat_id = "2147839041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 69 6d 75 6c 61 74 69 6f 6e 52 65 6d 6f 6e 74 65 65 53 6b 69 2e 54 31 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 2, accuracy: High
        $x_1_2 = "SimulationRemonteeSki" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABJB_2147839198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABJB!MTB"
        threat_id = "2147839198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 05 08 6f ?? ?? ?? 0a 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 13 06 de 59 09 2b cc 07 2b cb 6f ?? ?? ?? 0a 2b c6 13 04 2b c4 08 2b c3 11 04 2b c1 6f ?? ?? ?? 0a 2b bc 08 2b bb 09 2c 06 09 6f ?? ?? ?? 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBBK_2147839701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBBK!MTB"
        threat_id = "2147839701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 66 64 73 73 66 64 66 73 67 66 68 00 66 73 73 6a 66 73 66 66 64 66 67 00 73 6a 66 61 64}  //weight: 1, accuracy: High
        $x_1_2 = {06 07 08 09 02 03 28 25 01 00 06 fe 1a}  //weight: 1, accuracy: High
        $x_1_3 = "kfdssfdfsgfh" ascii //weight: 1
        $x_1_4 = "fssjfsffdfg" ascii //weight: 1
        $x_1_5 = "wssffssdv" ascii //weight: 1
        $x_1_6 = "Rfc2898DeriveBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ACE_2147840881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ACE!MTB"
        threat_id = "2147840881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0d 2b 19 06 09 6f 1b 00 00 0a 0c 08 03 61 d1 0c 07 08 6f 1c 00 00 0a 26 09 17 58 0d 09 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARC_2147840882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARC!MTB"
        threat_id = "2147840882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 06 18 5b 08 06 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 06 18 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARC_2147840882_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARC!MTB"
        threat_id = "2147840882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 01 02 11 01 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 20 06 00 00 00 7e ?? 01 00 04 7b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARC_2147840882_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARC!MTB"
        threat_id = "2147840882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 04 00 00 04 28 32 00 00 0a 04 6f 33 00 00 0a 6f 34 00 00 0a 0a 7e 03 00 00 04 06 6f 35 00 00 0a 00 7e 03 00 00 04 18 6f 36 00 00 0a 00 02 03 05 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARC_2147840882_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARC!MTB"
        threat_id = "2147840882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 16 0c 2b 63 03 08 03 8e 69 5d 1f 20 59 1f 20 58 03 08 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 61 28 ?? ?? ?? 0a 03 08 20 8a 10 00 00 58 20 89 10 00 00 59 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARC_2147840882_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARC!MTB"
        threat_id = "2147840882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 08 2b 11 04 11 06 11 08 91 6f ?? 00 00 0a 11 08 17 58 13 08 11 08 03 32 ea}  //weight: 1, accuracy: Low
        $x_2_2 = {16 13 08 2b 34 09 11 08 8f ?? 00 00 01 25 47 11 04 11 08 58 1f 11 5a 20 00 01 00 00 5d d2 61 d2 52 11 04 1f 1f 5a 09 11 08 91 58 20 00 01 00 00 5d 13 04 11 08 17 58 13 08 11 08 09 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARS_2147840883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARS!MTB"
        threat_id = "2147840883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 08 03 8e 69 5d 7e 03 01 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 19 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARS_2147840883_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARS!MTB"
        threat_id = "2147840883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0b 06 8e 69 17 59 0c 38 16 00 00 00 06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARS_2147840883_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARS!MTB"
        threat_id = "2147840883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 16 0c 2b 46 03 08 03 8e 69 5d 1b 59 1b 58 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 0a 03 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARS_2147840883_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARS!MTB"
        threat_id = "2147840883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 22 2b 4a 00 11 22 11 04 5d 13 23 11 22 17 58 11 04 5d 13 24 07 11 24 91 20 00 01 00 00 58 13 25 07 11 23 91 13 26 11 26 08 11 22 1f 16 5d 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARS_2147840883_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARS!MTB"
        threat_id = "2147840883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 8d ?? 00 00 01 0a 16 0b 38 ?? 00 00 00 06 07 02 07 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARS_2147840883_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARS!MTB"
        threat_id = "2147840883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 7e 01 00 00 04 07 6f ?? ?? ?? 0a 00 7e 01 00 00 04 18 6f ?? ?? ?? 0a 00 02 05 03 04 16 28 ?? ?? ?? 06 0c 2b 00 08 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "salamanca" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARS_2147840883_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARS!MTB"
        threat_id = "2147840883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 38 3f 00 00 00 28 ?? ?? ?? 06 75 01 00 00 1b 28 ?? ?? ?? 0a 0b d0 01 00 00 01 28 ?? ?? ?? 0a 72 01 00 00 70 28 ?? ?? ?? 0a 07 14 6f ?? ?? ?? 0a 75 02 00 00 1b 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARS_2147840883_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARS!MTB"
        threat_id = "2147840883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 20 00 11 0a 11 0f 8f ?? 00 00 01 25 47 11 0b 11 0f 11 0b 8e 69 5d 91 61 d2 52 00 11 0f 17 58 13 0f 11 0f 11 0a 8e 69}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 21 00 11 09 11 08 11 0d 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 0d 18 58 13 0d 11 0d 11 08 6f ?? 00 00 0a fe 04 13 0e 11 0e 2d ce}  //weight: 2, accuracy: Low
        $x_1_3 = "WaggerApp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASR_2147840884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASR!MTB"
        threat_id = "2147840884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 03 00 00 01 0d 16 13 04 2b 1c 09 11 04 18 5b 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 04 18 58 13 04 11 04 08 32 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASR_2147840884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASR!MTB"
        threat_id = "2147840884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 0e 1f 1c 28 3f 00 00 06 13 10 2b c3 11 07 11 0e 28 3d 00 00 06 16 13 10 2b b5 2b 21 11 05 17 33 0f 06 6f 6d 00 00 0a 11 07 28 3d 00 00 06 2b 0d 06 6f 6d 00 00 0a 11 07 28 20 00 00 06 11 07 16 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 06 03 17 59 28 ?? 00 00 06 0b 02 06 03 28 ?? 00 00 06 0c 02 07 06 8e 69 58 28 ?? 00 00 2b 08 07 59 06 8e 69 59 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 06 00 00 04 02 7e 06 00 00 04 02 91 7e 05 00 00 04 7e 1d 00 00 04 1f 7f 7e 1d 00 00 04 1f 7f 91 02 60 20 a0 00 00 00 5f 9c 59 7e 07 00 00 04 59 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 0b 16 0c 2b 11 02 08 02 08 91 20 d2 00 00 00 61 b4 9c 08 1d d6 0c 08 07 31 eb 14 0a 00 28 ?? 01 00 0a 0d 09 02 28 ?? 01 00 0a 00 09 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 1e 00 00 0a 0b 73 1f 00 00 0a 0c 07 16 73 20 00 00 0a 73 21 00 00 0a 0d 09 08 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc 08 6f ?? ?? ?? 0a 13 04 de 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 06 16 07 06 8e 69 28 ?? 00 00 0a 07 06 8e 69 1f 10 12 02 28}  //weight: 1, accuracy: Low
        $x_1_2 = {0c 08 07 17 73 1f 00 00 0a 0d 02 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 13 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 2b 15 00 06 08 06 08 91 07 08 07 8e 69 5d 93 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04}  //weight: 1, accuracy: High
        $x_1_2 = {a2 25 1a 11 18 a2 25 1b 72 ?? ?? ?? 70 a2 25 1c 11 0e a2 25 1d 11 08 a2 25 1e 11 0d a2 25 1f 09 11 13 a2 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1b 8d 41 00 00 01 25 16 28 ?? 00 00 06 6f ?? 00 00 06 a2 25 17 07 72 ?? 02 00 70 6f ?? 00 00 0a 75 ?? 00 00 01 a2 25 18 07 72 ?? 02 00 70 6f ?? 00 00 0a 75 ?? 00 00 01 a2 25 19 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 02 28 ?? ?? ?? 0a 0c dd 08 00 00 00 26 14 0d dd 33 00 00 00 73 e8 00 00 0a 13 04 08 73 e9 00 00 0a 13 05 11 05 11 04 06 07 6f ?? ?? ?? 0a 16 73 eb 00 00 0a 13 06 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = "HuidTeac" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 01 2a 00 38 00 00 00 00 00 72 51 00 00 70 28 ?? ?? ?? 06 13 00 38 00 00 00 00 28}  //weight: 1, accuracy: Low
        $x_1_2 = {02 8e 69 17 59 13 01 20 01 00 00 00 7e 61 04 00 04 7b b5 04 00 04 39 ?? ?? ?? ff 26 20 01 00 00 00 38 ?? ?? ?? ff 11 03 17 58 13 03 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 0a 38 17 00 00 00 00 72 93 00 00 70 28 ?? ?? ?? 06 0a dd 09 00 00 00 26 dd 00 00 00 00 06 2c e6 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {73 29 00 00 0a 0a 02 28 06 00 00 2b 6f 2b 00 00 0a 0b 38 0e 00 00 00 07 6f 2c 00 00 0a 0c 06 08 6f 2d 00 00 0a 07 6f 2e 00 00 0a 2d ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 00 06 6f b6 00 00 0a 0c 2b 1e 12 02 28 b7 00 00 0a 0d 09 6f b5 00 00 06 16 fe 01 13 04 11 04 2c 07 09 6f b8 00 00 06 00 12 02}  //weight: 1, accuracy: High
        $x_1_2 = {0a 2b 1d 12 00 28 b7 00 00 0a 0b 07 6f b5 00 00 06 16 fe 01 0c 08 2c 08 07 02 6f b7 00 00 06 00 12 00 28 b8 00 00 0a 2d da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 00 07 13 07 16 13 08 2b 43 11 07 11 08 9a 0d 00 09 6f ?? ?? ?? 0a 72 a5 00 00 70 6f ?? ?? ?? 0a 16 fe 01 13 09 11 09 2d 1c 00 12 02 08 8e 69 17 58 28 ?? ?? ?? 2b 00 08 08 8e 69 17 59 09 6f ?? ?? ?? 0a a2 00 00 11 08 17 58 13 08 11 08 11 07 8e 69 fe 04 13 09 11 09 2d af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 de f1 02 06 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 28 ?? 00 00 0a 02 73 ?? 00 00 0a 25 72 ?? 00 00 70 03 28 ?? 00 00 0a 6f ?? 00 00 0a 25 1f 0f 1f 14 73 ?? 00 00 0a 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 91 1e 5d 0b 02 7b ?? 00 00 04 06 18 58 02 7b ?? 00 00 04 5d 91 0c 02 7b ?? 00 00 04 06 19 58 02 7b ?? 00 00 04 5d 91 0d 02 03 06 91 28}  //weight: 2, accuracy: Low
        $x_1_2 = "investdirectinsurance.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARO_2147841227_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARO!MTB"
        threat_id = "2147841227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da}  //weight: 3, accuracy: Low
        $x_2_2 = "inspirecollege.co.uk/trashss/Jpmfwq.wav" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AOS_2147841230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AOS!MTB"
        threat_id = "2147841230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 14 00 00 0a 18 2d 03 26 2b 14 0a 2b fb 00 06 28 0f 00 00 06 6f 15 00 00 0a de 03 26 de 00 06 6f 16 00 00 0a 2c e7 28 17 00 00 0a 06 16 6f 18 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASO_2147841422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASO!MTB"
        threat_id = "2147841422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 20 00 00 0a 6f 21 00 00 0a 28 22 00 00 0a 0c de 17 26 20 d0 07 00 00 28 23 00 00 0a de 00 06 17 58 0a 06 1b 32 c2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ACR_2147841821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ACR!MTB"
        threat_id = "2147841821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 06 6f 23 00 00 0a 16 2d bc 06 6f 24 00 00 0a 16 6a 31 44 2b 0a 0d 2b c5 13 04 2b cf 0a 2b d5 06 6f 1f 00 00 0a 0c 06 6f 25 00 00 0a 07 08 16 08 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARR_2147842159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARR!MTB"
        threat_id = "2147842159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 14 7d 07 00 00 04 02 28 ?? ?? ?? 0a 00 00 02 20 f4 01 00 00 28 ?? ?? ?? 0a 00 02 20 bc 02 00 00 28 ?? ?? ?? 0a 00 02 72 01 00 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARR_2147842159_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARR!MTB"
        threat_id = "2147842159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 15 2b 19 00 11 0f 11 15 11 0f 11 15 91 20 d2 02 00 00 59 d2 9c 00 11 15 17 58 13 15 11 15 11 0f 8e 69}  //weight: 2, accuracy: High
        $x_1_2 = "2023CryptsDone\\DarkModeForms\\obj\\Debug\\DarkModeForms.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARR_2147842159_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARR!MTB"
        threat_id = "2147842159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 06 2b 30 00 11 06 11 04 5d 13 09 11 06 11 04 5b 13 0a 09 11 09 11 0a 6f ?? ?? ?? 0a 13 0b 08 12 0b 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 06 17 58 13 06 00 11 06 11 04 11 05 5a fe 04 13 0c 11 0c 2d c1}  //weight: 2, accuracy: Low
        $x_1_2 = "ChargingPile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARR_2147842159_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARR!MTB"
        threat_id = "2147842159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 06 72 97 18 00 70 6f ?? ?? ?? 0a 74 02 00 00 1b 0c 08 28 ?? ?? ?? 0a 00 07 08 6f ?? ?? ?? 0a 00 07 06 72 a3 18 00 70 6f ?? ?? ?? 0a 74 02 00 00 1b 6f ?? ?? ?? 0a 00 07 06 72 af 18 00 70 6f ?? ?? ?? 0a 74 02 00 00 1b 6f ?? ?? ?? 0a 00 02 28}  //weight: 2, accuracy: Low
        $x_1_2 = "SehirTahminEtmeOyunu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RE_2147842329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RE!MTB"
        threat_id = "2147842329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 13 26 2b 67 2b 6b 72 ?? 00 00 70 6f ?? 00 00 0a 2c 07 2b 03 0c 2b eb 08 2a 07 17 58 17 2c fb 0b 07 06 8e 69 1e 2c f4 32 ca 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EAC_2147842558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EAC!MTB"
        threat_id = "2147842558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 91 13 06 02 74 ?? 00 00 1b 11 04 09 11 04 11 05 5d 91 11 06 61 b4 9c 11 04 17 d6 13 04 00 11 04 20 [0-4] fe 01 16 fe 01 13 0a 11 0a 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AKR_2147843055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AKR!MTB"
        threat_id = "2147843055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 6a 13 0c 2b 5c 00 09 17 58 20 ?? ?? ?? 00 5f 0d 11 04 11 06 09 95 58 20 ?? ?? ?? 00 5f 13 04 11 06 09 95 13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 11 07 11 0c d4 07 11 0c d4 91 11 06 11 06 09 95 11 06 11 04 95 58 20 ?? ?? ?? 00 5f 95 61 28 ?? ?? ?? 0a 9c 00 11 0c 17 6a 58 13 0c 11 0c 11 07 8e 69 17 59 6a fe 02 16 fe 01 13 0d 11 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASE_2147843165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASE!MTB"
        threat_id = "2147843165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1a 58 4a 02 8e 69 5d 02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 06 1a 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAC_2147843423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAC!MTB"
        threat_id = "2147843423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 2b 11 00 06 09 11 04 28 02 00 00 2b 6f 71 00 00 0a 00 00 07 09 16 09 8e 69 6f 72 00 00 0a 25 13 04 16 fe 02 13 05 11 05 2d d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAC_2147843423_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAC!MTB"
        threat_id = "2147843423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 2b 42 03 08 03 8e 69 5d 7e 91 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 d0 00 00 06 03 08 1e 58 1d 59 03 8e 69 5d 91 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ATS_2147843596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ATS!MTB"
        threat_id = "2147843596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 13 06 2b 1a 00 09 11 06 08 11 06 91 07 11 06 07 8e 69 5d 91 61 d2 9c 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 2d d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EAU_2147843657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EAU!MTB"
        threat_id = "2147843657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 02 2a 00 02 72 ?? 00 00 70 28 ?? 00 00 06 13 00 38 00 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 13 01 38 00 00 00 00 02 11 01 28 ?? 00 00 06 13 02 38 00 00 00 00 dd}  //weight: 3, accuracy: Low
        $x_2_2 = "80.66.75.36/p-Jswztp.bmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBCO_2147843674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBCO!MTB"
        threat_id = "2147843674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 11 0c d4 07 11 0c d4 91 11 06 11 06 09 95 11 06 11 04 95 58 20 ff 00 00 00 5f 95 61}  //weight: 1, accuracy: High
        $x_1_2 = "c0a0ddb203dd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ALA_2147844091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ALA!MTB"
        threat_id = "2147844091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 01 2a 00 72 0d 00 00 70 28 0d 00 00 06 13 00 38 00 00 00 00 28 14 00 00 0a 11 00 6f 15 00 00 0a 28 16 00 00 0a 28 0b 00 00 06 13 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NEAC_2147844169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NEAC!MTB"
        threat_id = "2147844169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "52d55e2d-2381-4952-b43b-dd0c25deff28" ascii //weight: 5
        $x_2_2 = "war.pdb" ascii //weight: 2
        $x_2_3 = "yPmhuXPvvF" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EAV_2147844195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EAV!MTB"
        threat_id = "2147844195"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 72 01 00 00 70 6f ?? 00 00 0a 11 02 28 ?? 00 00 0a 72 01 00 00 70 6f ?? 00 00 0a 8e 69 5d 91 7e ?? 00 00 04 11 02 91 61 d2 6f ?? 00 00 0a 38}  //weight: 4, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBCY_2147844229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBCY!MTB"
        threat_id = "2147844229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 72 38 03 00 70 28 ?? 00 00 06 74 ?? 00 00 01 72 3e 03 00 70 72 42 03 00 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 1f 2d 9d}  //weight: 1, accuracy: Low
        $x_1_2 = "AF.y2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AOO_2147844427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AOO!MTB"
        threat_id = "2147844427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0d 2b 13 00 07 09 06 09 9a 1f 10 28 50 00 00 0a 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 2, accuracy: High
        $x_1_2 = "BlackJackAkash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AROS_2147844448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AROS!MTB"
        threat_id = "2147844448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 07 8e 69 17 59 0d 2b 21 0a 2b dc 0b 2b ed 0c 2b ef 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 32 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PSJU_2147844535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PSJU!MTB"
        threat_id = "2147844535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 17 11 11 11 16 11 17 6f 24 00 00 0a 00 00 11 14 17 58 13 14 11 14 11 13 8e 69 32 c7 00 72 97 03 00 70 13 18 1f 10 28 1f 00 00 0a 13 19 72 b7 03 00 70 13 1a 72 1d 04 00 70 13 1b 72 73 04 00 70 73 25 00 00 0a 28 26 00 00 0a 28 27 00 00 0a 74 07 00 00 02 13 1c 7e 01 00 00 04 2c 02 2b 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EAS_2147844938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EAS!MTB"
        threat_id = "2147844938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 7e ?? 01 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 01 00 06 03 08 1d 58 1c 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f 26 08 6a 03 8e 69 15 2c fc 17 59 6a 06 17 58 16 2d fb 6e 5a 16 2d f5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDG_2147845145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDG!MTB"
        threat_id = "2147845145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f7df40b6-9035-4c7a-8437-9ba2d9c54b81" ascii //weight: 1
        $x_1_2 = "JhHh726" ascii //weight: 1
        $x_1_3 = "RIAM" ascii //weight: 1
        $x_1_4 = "MIAXS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBDK_2147845676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBDK!MTB"
        threat_id = "2147845676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 14 d0 ?? 00 00 01 28 ?? 00 00 0a 72 ?? ?? ?? 70 17 8d ?? 00 00 01 25 16 07 25 0c 1c 6f ?? 00 00 0a a2 25 13 05 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FAT_2147845878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FAT!MTB"
        threat_id = "2147845878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 11 05 11 04 6f ?? 00 00 0a 11 05 18 6f ?? 00 00 0a 11 05 18 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 11 06 07 16 07 8e 69 6f ?? 00 00 0a 13 07 28 ?? 00 00 0a 11 07 6f ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 13 0a de 52 02 38 ?? ff ff ff 6f ?? 00 00 0a 38 ?? ff ff ff 0a 38 ?? ff ff ff 06 38 ?? ff ff ff 28 ?? 00 00 0a 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FAU_2147845948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FAU!MTB"
        threat_id = "2147845948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 13 00 38 00 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 13 01 38 00 00 00 00 02 11 01 28 ?? 00 00 06 13 02 38 00 00 00 00 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAR_2147846136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAR!MTB"
        threat_id = "2147846136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 07 09 6f ?? ?? ?? 0a 00 07 18 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 13 04 11 04 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAR_2147846136_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAR!MTB"
        threat_id = "2147846136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 18 2d 03 26 2b 1a 0a 2b fb 00 72 dd 03 00 70 28 ?? ?? ?? 06 1b 2d 03 26 de 09 0a 2b fb}  //weight: 1, accuracy: Low
        $x_1_2 = {1a 2d 12 26 02 28 ?? ?? ?? 2b 6f ?? ?? ?? 0a 1d 2d 06 26 2b 06 0a 2b ec 0b 2b 00 2b 16 07 6f ?? ?? ?? 0a 1c 2d 0a 26 06 08 6f ?? ?? ?? 0a 2b 03 0c 2b f4 07 6f 09 00 00 0a 2d e2 de 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FAH_2147846231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FAH!MTB"
        threat_id = "2147846231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 0a 03 08 1f 09 58 1e 59 03 8e 69 5d 91 59 20 ?? 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 16 2d 02 17 58 0c 08 6a 03 8e 1b 2c 01 69 17 59 6a 06 17 58 6e 5a 31 a8 0f 01 03 8e 69 17 59}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABTT_2147846302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABTT!MTB"
        threat_id = "2147846302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4c 00 6f 00 6f 00 6d 00 69 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 2, accuracy: High
        $x_1_2 = "14f759be-b6ee-49ec-87bb-983a9ccdf051" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABTG_2147846602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABTG!MTB"
        threat_id = "2147846602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 15 17 2d 0d 26 28 ?? 00 00 2b 28 ?? 00 00 2b 2b 03 26 2b f1 2a}  //weight: 2, accuracy: Low
        $x_2_2 = "Wiwzokfshcoozngypst" wide //weight: 2
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PSA_2147847223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PSA!MTB"
        threat_id = "2147847223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 0f 00 00 0a 73 10 00 00 0a 28 ?? ?? ?? 0a 72 0d 00 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 25 06 6f ?? ?? ?? 0a 25 18 6f ?? ?? ?? 0a 73 01 00 00 06 28 ?? ?? ?? 06 0b 6f ?? ?? ?? 0a 07 16 07 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = "Kyhguyug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBDX_2147847576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBDX!MTB"
        threat_id = "2147847576"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Syste_m.Refl_ection.As_sembly" wide //weight: 1
        $x_1_2 = "Ge_tExp_ortedTy_pes" wide //weight: 1
        $x_1_3 = "Sy_stem.Refl_ection.Asse_mbly" wide //weight: 1
        $x_1_4 = "Ssuauadgdiydvidshvzsdykb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABXN_2147847815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABXN!MTB"
        threat_id = "2147847815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {14 0a 38 26 00 00 00 00 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0a dd ?? 00 00 00 26 dd 00 00 00 00 06 2c d7}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABYJ_2147848242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABYJ!MTB"
        threat_id = "2147848242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? 00 00 06 0a dd ?? 00 00 00 26 de ec 06 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDH_2147848263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDH!MTB"
        threat_id = "2147848263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c91e4688-bcbd-44c7-b0c8-5eb2baa09aef" ascii //weight: 1
        $x_1_2 = "Lyyonmqf" ascii //weight: 1
        $x_1_3 = "0c94cef8-34a4-47d5-9427-75edf08f426d" ascii //weight: 1
        $x_1_4 = "Syfbdgjtcrwegpwjyafbqh.Fquqauuovede" wide //weight: 1
        $x_1_5 = "Oemutptkfpyfcgws" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 2b f1 0b 2b f8 02 50 06 91 17 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 13 08 2b 13 00 07 08 11 08 09 28 ?? 00 00 06 00 00 11 08 17 58 13 08 11 08 07 6f ?? 00 00 0a 2f 0b 08 6f ?? 00 00 0a 09 fe 04 2b 01 16 13 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 2b 33 02 0d 16 13 04 09 12 04 28 ?? 00 00 0a 07 06 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 0b 11 04 2c 06 09 28 ?? 00 00 0a dc 08 18 58 0c 08 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 12 00 06 07 17 07 1f 1f 5f 62 1f 64 5a 9e 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e4}  //weight: 2, accuracy: High
        $x_1_2 = {16 0c 2b 18 00 06 19 28 ?? 00 00 06 0a 04 07 08 91 6f ?? 01 00 0a 00 00 08 17 58 0c 08 03 fe 04 0d 09 2d e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 26 7e 03 00 00 04 18 6f 42 00 00 0a 00 02 02 02 03 03 03 04 03 04 0e 04 28 08 00 00 06 0a 2b 00}  //weight: 1, accuracy: High
        $x_1_2 = {7e 04 00 00 04 28 3e 00 00 0a 02 6f 3f 00 00 0a 6f 40 00 00 0a 0a 7e 03 00 00 04 06 25 0b 6f 41 00 00 0a 00 07 0c 2b 00 08 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 06 11 07 6f ?? 00 00 0a 13 08 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 20 00 1e 01 00 13 09 08 6f ?? 00 00 0a 09 6f ?? 00 00 0a d6 11 09 fe 02 16 fe 01 13 0a 11 0a 2c 0c 00 08 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 16 13 04 2b 1f 08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da 06 08 6f ?? 00 00 0a 06 16 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "Pagamento.Novobanco.pdf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0a 06 72 91 01 00 70 6f ?? 00 00 0a 26 06 6f ?? 00 00 0a 26 02 73 a7 00 00 0a 7d 16 00 00 04 02 73 a8 00 00 0a 7d 17 00 00 04}  //weight: 2, accuracy: Low
        $x_1_2 = {16 0b 2b 0e 00 1f 19 28 ?? 00 00 0a 00 00 07 17 58 0b 07 20 96 00 00 00 fe 04 0c 08 2d e6}  //weight: 1, accuracy: Low
        $x_1_3 = "3db23c45-14cc-45be-9c58-70c6738b59b7" ascii //weight: 1
        $x_1_4 = "FileRenamer\\obj\\Debug\\FIco.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARE_2147848365_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARE!MTB"
        threat_id = "2147848365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0a 2b 0e 20 e8 03 00 00 28 ?? 00 00 0a 06 17 58 0a 06 1b 32 ee}  //weight: 2, accuracy: Low
        $x_1_2 = "mdnckhzntmvk4sbnewqcf7t5ypa27567" ascii //weight: 1
        $x_1_3 = "aem78u4jy3hppwkaqwjj2jgmuzmar4d8" ascii //weight: 1
        $x_1_4 = "ccvk3ycfbz2ptmbjnkzpexr4s5bjfnmb" ascii //weight: 1
        $x_1_5 = "tmf4w9dq9xyfblsp8fu3ytwh8zx8avad" ascii //weight: 1
        $x_1_6 = "79e93ek6jrwnqqwyypgeft4qskerzjwf" ascii //weight: 1
        $x_1_7 = "rcrf5k9hyfqraq34f6ab3fxn5e7y5rmp" ascii //weight: 1
        $x_1_8 = "f763dqn9gaqcyh7k7xvq78jwdex8sacs" ascii //weight: 1
        $x_1_9 = "6700a56d-c0ac-4c2a-bfad-3353181481e5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABVC_2147848550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABVC!MTB"
        threat_id = "2147848550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 11 02 6f ?? 00 00 0a 25 26 11 03 1f 18 28 ?? 00 00 06 14 14 11 06 74 ?? 00 00 1b 6f ?? 00 00 0a 25 26 26 38 ?? ff ff ff 28 ?? 00 00 06 25 26 28 ?? 00 00 0a 25 26 13 05}  //weight: 3, accuracy: Low
        $x_1_2 = "22206fb0-c980-4ac8-8294-8621502cf186" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABYS_2147848676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABYS!MTB"
        threat_id = "2147848676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 72 0d 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0a dd ?? 00 00 00 26 dd 00 00 00 00 06 2c d1 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AABI_2147848944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AABI!MTB"
        threat_id = "2147848944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 01 00 06 03 08 1a 58 19 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 b2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RPX_2147848974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RPX!MTB"
        threat_id = "2147848974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 08 1a 58 19 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RPX_2147848974_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RPX!MTB"
        threat_id = "2147848974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 17 13 04 16 13 05 2b 23 00 06 09 11 05 58 91 07 11 05 91 fe 01 16 fe 01 13 06 11 06 2c 06 00 16 13 04 2b 14 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 07 11 07 2d d0}  //weight: 1, accuracy: High
        $x_1_2 = "@rhM*AzA!7%c@P4obzD8s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RPX_2147848974_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RPX!MTB"
        threat_id = "2147848974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "141.98.6.202" wide //weight: 1
        $x_1_2 = "Inajmllbw.dat" wide //weight: 1
        $x_1_3 = "9syQWIT+CZSEb6hTMPNQGA==" wide //weight: 1
        $x_1_4 = "99QVqpkysMQ=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 1f 1f 5a 11 06 1f 11 5a 58 09 74 ?? ?? ?? 1b 8e 69 17 59 5f 13 08 11 1b 20 ?? ?? ?? ?? 91 19 5b 13 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 16 13 22 2b 2f 11 07 11 06 8e 69 5d 13 23 11 06 11 23 11 21 11 22 91 9c 03 11 21 11 22 91 6f ?? 00 00 0a 11 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 38 16 0b 2b 21 08 06 07 28 ?? ?? ?? 06 13 09 09 12 09 28 ?? ?? ?? 0a 8c 07 00 00 01 28 ?? ?? ?? 06 26 07 17 58 0b 07 08 28 ?? ?? ?? 06 fe 04 13 06 11 06 2d d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 0c 2b 21 00 11 07 11 0c 11 06 08 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 9d 00 11 0c 17 58 13 0c 11 0c 11 07 8e 69 fe 04 13 0d 11 0d 2d d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 16 11 06 6f 81 00 00 0a 00 00 08 11 05 16 11 05 8e 69 6f 82 00 00 0a 25 13 06 16 fe 02}  //weight: 1, accuracy: High
        $x_1_2 = {7b 28 00 00 04 59 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 5a 06 5a 07 07 5a 58 08 08 5a 58 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0b 2b 30 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 6f ?? 00 00 0a 04 32 01 2a 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 2b 15 02 07 03 28 12 00 00 06 2c 07 06 07 6f 35 00 00 0a 07 17 58 0b 07 02 8e 69 32 e5}  //weight: 1, accuracy: High
        $x_1_2 = {0a 16 0b 2b 13 06 07 02 28 1f 00 00 06 07 6f 6c 00 00 0a a2 07 17 58 0b 07 02 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 16 9a 13 04 19 8d ?? 00 00 01 25 16 02 7b ?? 00 00 04 a2 25 17 02 7b ?? 00 00 04 a2 25 18 72 ?? 08 00 70 a2 13 05 72 ?? 08 00 70 17 8d ?? 00 00 01 25 16 1f 58 9d 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 16 0d 16 0d 2b 6a 06 09 06 8e 69 5d 1f 37 59 1f 37 58 06 09 06 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 19 58 19 59 91 08 09 08 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 1c 58 1c 59 91 61 06 09 20 11 02 00 00 58 20 10 02 00 00 59 06 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 1c 58 1c 59 91 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 17 2b 63 00 11 06 17 58 20 ff 00 00 00 5f 13 06 11 05 11 04 11 06 95 58 20 ff 00 00 00 5f 13 05 02 11 04 11 06 8f 7d 00 00 01 11 04 11 05 8f 7d 00 00 01 28 ?? 00 00 06 00 11 04 11 06 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 18 09 11 17 07 11 17 91 11 04 11 18 95 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 3a 16 0b 2b 13 02 06 07 03 04 28 ?? 00 00 06 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08 2d d4}  //weight: 2, accuracy: Low
        $x_1_2 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 07 05 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a 12 29 28 ?? 00 00 0a 58 13 0a 11 0b 12 29 28 ?? 00 00 0a 58 13 0b 11 0c 12 29 28 ?? 00 00 0a 58 13 0c 12 29 28 ?? 00 00 0a 12 29 28 ?? 00 00 0a 58 12 29 28 ?? 00 00 0a 58 13 2a 11 2a 11 0d 31 04 11 2a 13 0d 11 2a 11 0e 2f 04 11 2a 13 0e 11 27 11 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 9a 0c 08 19 8d 47 00 00 01 25 16 7e 2e 00 00 04 16 9a a2 25 17 7e 2e 00 00 04 17 9a a2 25 18}  //weight: 2, accuracy: High
        $x_2_2 = {16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc}  //weight: 2, accuracy: Low
        $x_1_3 = "TournamentLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 0b 2b 5f 00 11 05 17 58 20 ff 00 00 00 5f 13 05 11 06 11 04 11 05 95 58 20 ff 00 00 00 5f 13 06 02 11 04 11 05 8f ?? 00 00 01 11 04 11 06 8f ?? 00 00 01 28 ?? 00 00 06 00 11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 0c 02 11 0b 07 09 11 04 11 0c 28 ?? 00 00 06 00 00 11 0b 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 12 2b 63 00 11 07 17 58 20 ff 00 00 00 5f 13 07 11 05 11 04 11 07 95 58 20 ff 00 00 00 5f 13 05 11 04 11 07 95 13 06 11 04 11 07 11 04 11 05 95 9e 11 04 11 05 11 06 9e 11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 13 11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c 00 11 12 17 58 13 12 11 12 09 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 16 0b 25 06 02 02 8e 69 12 01 28 ?? 00 00 06 26 7e ?? 00 00 0a 0c 7e ?? 00 00 0a 16 20 ff 0f 00 00 28 ?? 00 00 0a 7e ?? 00 00 0a 1a 12 02 28}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 16 0b 2b 22 06 07 9a 0c 08 6f 2f 00 00 0a 6f 30 00 00 0a 02 28 14 00 00 0a 2c 07 08 6f 31 00 00 0a 2a 07 17 58 0b 07 06 8e 69 32 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 00 09 07 08 6f ?? 00 00 0a 00 00 de 0b 09 2c 07 09 6f ?? 00 00 0a 00 dc 08 28}  //weight: 1, accuracy: Low
        $x_2_2 = {0a 00 25 17 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 0a 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 de 23 0b 00 72 ?? 01 00 70 07 6f}  //weight: 2, accuracy: Low
        $x_3_3 = {0a 00 25 17 6f ?? 00 00 0a 00 25 72 ?? 01 00 70 6f ?? 00 00 0a 00 0a 00 06 28 ?? 00 00 0a 26 00 de 05 26 00 00 de 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RestaurantApp.AccountControl" ascii //weight: 1
        $x_1_2 = "RestaurantApp.ContactControl" ascii //weight: 1
        $x_1_3 = "RestaurantApp.DefaultControl" ascii //weight: 1
        $x_1_4 = "RestaurantApp.LoginControl" ascii //weight: 1
        $x_1_5 = "RestaurantApp.MenuControl" ascii //weight: 1
        $x_1_6 = "RestaurantApp.NutritionControl" ascii //weight: 1
        $x_1_7 = "RestaurantApp.RestaurantControl" ascii //weight: 1
        $x_1_8 = "RestaurantApp.WelcomeControl" ascii //weight: 1
        $x_1_9 = "e04ccb7e-d82d-43c7-9946-138469ef830c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ARM_2147849040_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ARM!MTB"
        threat_id = "2147849040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SolaraBootstrapper\\bin\\Release\\Bootstrapper.pdb" ascii //weight: 2
        $x_2_2 = "New bootstrapper downloaded" wide //weight: 2
        $x_1_3 = "/silent /install" wide //weight: 1
        $x_1_4 = "WebView2 runtime installed successfully" wide //weight: 1
        $x_1_5 = "/install /quiet /norestart" wide //weight: 1
        $x_1_6 = "killing Solara.exe process" wide //weight: 1
        $x_1_7 = "killing node.exe process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MA_2147849125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MA!MTB"
        threat_id = "2147849125"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 13 05 16 13 06 11 05 12 06 28 ?? ?? ?? 0a 00 08 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 de 0d}  //weight: 5, accuracy: Low
        $x_5_2 = "http://80.66.75.37/" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AABZ_2147849257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AABZ!MTB"
        threat_id = "2147849257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 08 07 6f ?? 00 00 0a 13 13 16 0d 11 05 06 9a 20 09 75 f1 0d 28 ?? 01 00 06 28 ?? 00 00 0a 13 0c 11 0c 2c 0a 12 13 28 ?? 00 00 0a 0d 2b 44 11 05 06 9a 20 71 75 f1 0d 28 ?? 01 00 06 28 ?? 00 00 0a 13 0d 11 0d 2c 0a 12 13 28 ?? 00 00 0a 0d 2b 21 11 05 06 9a 20 79 75 f1 0d 28 ?? 01 00 06 28 ?? 00 00 0a 13 0e 11 0e 2c 08 12 13 28 ?? 00 00 0a 0d 11 06 09 6f ?? 00 00 0a 08 17 58 0c 08 11 08 fe 04 13 0f 11 0f 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GJY_2147849312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GJY!MTB"
        threat_id = "2147849312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 13 05 16 13 06 11 05 12 06 28 ?? ?? ?? 0a 00 08 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 de 0d 11 06 2c 08 11 05 28 ?? ?? ?? 0a 00 dc 00 11 04 18 58 13 04 11 04 07 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GJZ_2147849401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GJZ!MTB"
        threat_id = "2147849401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 13 05 16 13 06 11 05 12 06 28 ?? ?? ?? 0a 00 09 08 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 dd 10 00 00 00 11 06 39 ?? ?? ?? 00 11 05 28 ?? ?? ?? 0a 00 dc 00 11 04 18 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d ac}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBEO_2147849469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBEO!MTB"
        threat_id = "2147849469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sgfhjffffgdhjsrfhddfhfffaddsfsfsscfgdb" ascii //weight: 1
        $x_1_2 = "ffghrgfdfdffdffffkhsjd" ascii //weight: 1
        $x_1_3 = "ddfdjfffsfhgdffafcfdssfkfhgj" ascii //weight: 1
        $x_1_4 = "hdffhdfafffkdf" ascii //weight: 1
        $x_1_5 = "hfsdkffddfgfhseffdfaffdchd" ascii //weight: 1
        $x_1_6 = "RijndaelManaged" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABYR_2147849621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABYR!MTB"
        threat_id = "2147849621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 87 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 02 00 06 16 39 ?? 00 00 00 26 38 00 00 00 00 dd ?? ff ff ff 13 00 38 00 00 00 00 38 ?? ff ff ff 26}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AADD_2147850102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AADD!MTB"
        threat_id = "2147850102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 04 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "$$$$$$$$$$C$$$$$$$$$$$$reat$$$$$$$eIn$$$$$$$$$$stan$$$$$$$$$$$ce" wide //weight: 1
        $x_1_3 = "$$$$$Sy$$$$$$$$$$$s$$$$$$$$tem.A$$$$$$$$$$$$$$cti$$$$$$$va$$$$$$$$$$$$$$$tor$$$$$$$$$$$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AADM_2147850103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AADM!MTB"
        threat_id = "2147850103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CRM02.Properties.Resources.resources" ascii //weight: 2
        $x_1_2 = "CRM02.Properties" ascii //weight: 1
        $x_1_3 = "GetExportedTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBFZ_2147850549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBFZ!MTB"
        threat_id = "2147850549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hfsdkfdhghffshsfegfdafffdch" ascii //weight: 1
        $x_1_2 = "fhhfgdffrfffdkdfadhfghfdasdfh" ascii //weight: 1
        $x_1_3 = "sfhjffkfhgfdjsrfhdfdfhfffadsgfahsscffgdb" ascii //weight: 1
        $x_1_4 = "ddfdrhjfsfffghgdffafcfdssfkfhgj" ascii //weight: 1
        $x_1_5 = "jgacfsafdghhffffrfdsdgkfff" ascii //weight: 1
        $x_1_6 = "gdghdfgdsffhsfdgh" ascii //weight: 1
        $x_1_7 = "fsgfrgfafddhdffffkhsjd" ascii //weight: 1
        $x_1_8 = "hsfdohsd" ascii //weight: 1
        $x_1_9 = "RijndaelManaged" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBFX_2147850552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBFX!MTB"
        threat_id = "2147850552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 50 06 91 1c 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da}  //weight: 1, accuracy: High
        $x_1_2 = {57 15 02 08 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 08 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "WindowsFormsApp50.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBGA_2147850553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBGA!MTB"
        threat_id = "2147850553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 0f 04 00 70 6f ?? 00 00 0a 2d 0d 02 72 13 04 00 70 6f ?? 00 00 0a 2b 01 16 0d 09 2c 54 00 02 17 8d ?? 00 00 01 25 16 1f 2d 9d}  //weight: 1, accuracy: Low
        $x_1_2 = "8613d7b5415f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAEL_2147850702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAEL!MTB"
        threat_id = "2147850702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 0a 2b 1b 00 7e ?? 00 00 04 06 7e ?? 00 00 04 06 91 20 81 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 3, accuracy: Low
        $x_1_2 = "DownloadData" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAEP_2147850706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAEP!MTB"
        threat_id = "2147850706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 09 16 73 ?? 00 00 0a 13 04 20 03 00 00 00 38 ?? ff ff ff 11 09 11 0d 16 1a 28 ?? 00 00 06 26 20 02 00 00 00 38 ?? ff ff ff 11 0d 16 28 ?? 00 00 06 13 03 20 00 00 00 00 7e ?? 17 00 04 7b ?? 17 00 04 3a ?? ff ff ff 26}  //weight: 3, accuracy: Low
        $x_1_2 = "192.210.215.42/z/panel/uploads/Blnlvcclrdy.vdf" wide //weight: 1
        $x_1_3 = "SmA3aJ7pk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_CXGG_2147851447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.CXGG!MTB"
        threat_id = "2147851447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RW50ZXIgVmFsdWUgb2YgTiA6IA==" ascii //weight: 1
        $x_1_2 = "UG9wcGVkIEVsZW1lbnQ6IA==" ascii //weight: 1
        $x_1_3 = "ZGFkYWg=" ascii //weight: 1
        $x_1_4 = "VGhlIHZhbHVlIGlzOiA=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDI_2147851681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDI!MTB"
        threat_id = "2147851681"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 02 6f 1f 00 00 0a 25 26 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RPY_2147852301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RPY!MTB"
        threat_id = "2147852301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 01 00 6f 67 00 00 0a 20 03 00 00 00 66 20 02 00 00 00 63 65 8d 2e 00 00 01 25 20 40 fc 9e 24 20 bf 03 61 db 58 66 20 b4 be 87 e7 20 01 00 00 00 63 66 20 9e 20 3c 0c 61 9d 6f 68 00 00 0a fe 0e 02 00 20 1c 00 00 00 38 43 e8 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RPY_2147852301_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RPY!MTB"
        threat_id = "2147852301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 07 02 07 18 5a 18 6f 8a 00 00 0a 1f 10 28 8b 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc}  //weight: 1, accuracy: High
        $x_1_2 = "4D5A9~~3~~~04~~~FFFF~~B8~~~~~~~4~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~08~~~~" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_APM_2147852453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.APM!MTB"
        threat_id = "2147852453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 16 0b 03 17 33 20 02 7b 27 00 00 04 6f 73 00 00 0a 0b 07 15 33 05 28 56 00 00 06 02 7b 28 00 00 04 16 07 d2 9c 2a 02 7b 27 00 00 04 02 7b 28 00 00 04 06 03 06 59 6f 74 00 00 0a 0b 07 2d 05 28 56 00 00 06 06 07 58 0a 06 03 32 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PSUR_2147852913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PSUR!MTB"
        threat_id = "2147852913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 57 0a 00 06 20 03 00 00 00 38 b5 ff ff ff 11 08 11 08 28 58 0a 00 06 11 08 28 59 0a 00 06 6f 5f 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ADSR_2147853173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ADSR!MTB"
        threat_id = "2147853173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {15 0d 00 08 1f 3c 09 17 58 6f ?? ?? ?? 0a 0d 09 15 fe 01 16 fe 01 13 04 11 04 2c 4c 00 08 1f 3e 09 6f ?? ?? ?? 0a 13 05 11 05 15 fe 01 16 fe 01 13 06 11 06 2c 31 00 11 05 09 59 13 07 08 09 17 58 11 07 17 59 6f ?? ?? ?? 0a 13 08 02 7b 58 00 00 04 6f ?? ?? ?? 0a 09 17 58 11 07 17 59 11 08 6f ?? ?? ?? 0a 26 00 00 00 09 15 fe 01 16 fe 01 13 09 11 09 2d 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHU_2147853211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHU!MTB"
        threat_id = "2147853211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1a 58 4a 03 8e 69 5d 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 03 06 1a 58 4a 1f 15 58 1f 14 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 16 2d 8d 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 6a 03 8e 69 17 59 6a 06 4b 17 58 6e 5a 31 98 0f 01 03 8e 69 17 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AALT_2147888293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AALT!MTB"
        threat_id = "2147888293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 02 16 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAMB_2147888504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAMB!MTB"
        threat_id = "2147888504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 17 2c e8 09 03 16 03 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAMM_2147888666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAMM!MTB"
        threat_id = "2147888666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 06 7e ?? 00 00 04 06 07 28 ?? 00 00 06 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 1b 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 04 16 04 8e 69 28 ?? 00 00 06 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAMR_2147888824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAMR!MTB"
        threat_id = "2147888824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 02 03 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 16 03 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 8e 69 28 ?? 00 00 0a 28 ?? 00 00 06 26 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64CharArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBIC_2147888876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBIC!MTB"
        threat_id = "2147888876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 12 01 07 8e 69 11 04 8e 69 58 28 ?? 00 00 06 12 01 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = "QnovDRkgfnoOaikMMsqL.res" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAMT_2147888913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAMT!MTB"
        threat_id = "2147888913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 1a 58 4a 03 8e 69 5d 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? 00 00 0a 03 06 1a 58 4a 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAMU_2147888926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAMU!MTB"
        threat_id = "2147888926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 07 75 ?? 00 00 1b 11 04 1e 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 19 13 09 2b ?? 08 17 d6 0c 1e 13 09 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBIJ_2147889296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBIJ!MTB"
        threat_id = "2147889296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fghhfgsfffrfdfdffddshfdasdfh" ascii //weight: 1
        $x_1_2 = "sgfhjffffgdhjsrfhddfhfffadfsfsscfgdb" ascii //weight: 1
        $x_1_3 = "fhfsdsfhfdfhhs" ascii //weight: 1
        $x_1_4 = "sffdfggfs" ascii //weight: 1
        $x_1_5 = "cdfffdfafdfrsfsshdkfffgh" ascii //weight: 1
        $x_1_6 = "GetMethods" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAA_2147889487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAA!MTB"
        threat_id = "2147889487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 20 ff 00 00 00 5f 13 [0-20] 61 20 ff 00 00 00 5f [0-20] 58 20 00 01 00 00 5e 26 09 11 [0-30] 95 61 d2 9c 11 ?? 17 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAA_2147889487_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAA!MTB"
        threat_id = "2147889487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 11 0a 11 04 5d 13 0b 11 0a 11 05 5d 13 0c 08 11 0b 91 13 0d 09 11 0c 6f ?? 00 00 0a 13 0e 08 11 0a 17 58 11 04 5d 91 13 0f 11 0d 11 0e 11 0f 28 ?? 00 00 06 13 10 08 11 0b 11 10 20 00 01 00 00 5d d2 9c 00 11 0a 17 59 13 0a 11 0a 16 fe 04 16 fe 01 13 11 11 11 2d a7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAA_2147889487_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAA!MTB"
        threat_id = "2147889487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 02 11 04 9a 28 ?? 00 00 0a 1f 62 da b4 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 e1 08 6f ?? 00 00 0a 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 73 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 00 00 09 4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAA_2147889487_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAA!MTB"
        threat_id = "2147889487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 04 16 04 8e 69 6f ?? 00 00 0a 2a 73 2b 00 00 0a ?? 99 0a 2b 98 0b 2b 9e}  //weight: 1, accuracy: Low
        $x_1_2 = "cdhfdfgfdkffshdhdshdghf" ascii //weight: 1
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAOC_2147889526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAOC!MTB"
        threat_id = "2147889526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 15 09 5d 13 16 11 15 11 04 5d 13 17 07 11 16 91 13 18 08 11 17 6f ?? 00 00 0a 13 19 07 11 15 17 58 09 5d 91 13 1a 11 18 11 19 61 11 1a 59 20 00 01 00 00 58 13 1b 07 11 16 11 1b 20 00 01 00 00 5d d2 9c 00 11 15 17 59 13 15 11 15 16 fe 04 16 fe 01 13 1c 11 1c 2d a6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FAI_2147890038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FAI!MTB"
        threat_id = "2147890038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 20 00 01 00 00 28 ?? 00 00 06 09 20 80 00 00 00 28 ?? 00 00 06 03 07 20 30 75 00 00 73 ?? 00 00 0a 13 04 09 11 04 09 28 ?? 00 00 06 1e 5b 28 ?? 00 00 06 28 ?? 00 00 06 09 11 04 09 28 ?? 00 00 06 1e 5b 28 ?? 00 00 06 28 ?? 00 00 06 09 17 28 ?? 00 00 06 08 09 28 ?? 00 00 06 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 28 ?? 00 00 06 11 05 28 ?? 00 00 06 dd}  //weight: 1, accuracy: Low
        $x_1_2 = "VJggg3xmclv2va.lLOsem2e0gxmp4" wide //weight: 1
        $x_1_3 = "jje3ejttzmi" wide //weight: 1
        $x_1_4 = "l1PYE03y1kyilsXOhx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AOX_2147890047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AOX!MTB"
        threat_id = "2147890047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 04 17 73 94 00 00 0a 0c 28 ?? ?? ?? 06 16 9a 75 19 00 00 1b 0d 08 09 16 09 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_APQ_2147890052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.APQ!MTB"
        threat_id = "2147890052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 0b 16 0c 2b 15 02 08 02 08 9a 03 72 ?? 01 00 70 6f ?? ?? ?? 0a a2 08 17 d6 0c 08 07 31 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PAAZ_2147890329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PAAZ!MTB"
        threat_id = "2147890329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 7e 1d 00 00 04 06 7e 1d 00 00 04 06 91 20 4d 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 1d 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBJK_2147892182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBJK!MTB"
        threat_id = "2147892182"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 da 0d 0c 2b 1f 07 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 26 08 18 d6 0c 08 09 31 dd}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 6f 00 72 00 65 00 46 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 43 00 6c 00 61 00 73 00 73 00 31 00 00 09 4d 00 61 00 69 00 6e}  //weight: 1, accuracy: High
        $x_1_3 = {33 00 33 00 33 00 35 00 33 00 33 00 33 00 34 00 33 00 33 00 33 00 35 00 33 00 33 00 33 00 36 00 33 00 33 00 33 00 37 00 33 00 33 00 33 00 31 00 33}  //weight: 1, accuracy: High
        $x_1_4 = {57 35 a2 1d 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AARJ_2147892392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AARJ!MTB"
        threat_id = "2147892392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 08 14 0b 2b 0c 00 28 ?? 00 00 06 0b de 03 26 de 00 07 2c f1 73 ?? 00 00 0a 0c 07 73 ?? 00 00 0a 13 05 11 05 11 08 16 73 ?? 00 00 0a 13 06 11 06 08 6f ?? 00 00 0a de 08 11 06 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBJU_2147892803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBJU!MTB"
        threat_id = "2147892803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 00 38 00 4b 00 68 00 2b 00 7a 00 38 00 64 00 38 00 4a 00 65 00 31 00 58 00 54 00 6d 00 6b 00 49 00 34 00 39 00 73 00 31 00 4b 00 52 00 52 00 4c 00 53 00 34 00 63 00 37 00 70 00 70 00 61 00 2f 00 73}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 77 00 2f 00 73 00 78 00 4c 00 6f 00 32 00 55 00 50 00 7a 00 4e 00 66 00 2b 00 7a 00 45 00 75 00 6a 00 5a 00 51 00 2f 00 4d 00 31 00 2f 00 37 00 4d 00 53}  //weight: 1, accuracy: High
        $x_1_3 = "Selam123" wide //weight: 1
        $x_1_4 = "RC2CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AASI_2147892882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AASI!MTB"
        threat_id = "2147892882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 8e 69 8d ?? 00 00 01 0c 16 0d 38 ?? 00 00 00 08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAB_2147892945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAB!MTB"
        threat_id = "2147892945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASFG_2147894049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASFG!MTB"
        threat_id = "2147894049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 04 08 8e 69 5d 02 08 11 04 08 8e 69 5d 91 09 11 04 09 28 ?? 02 00 06 5d 28 ?? 02 00 06 61 28 ?? 02 00 06 08 11 04 17 58 08 8e 69 5d 91 28 ?? 02 00 06 59 20 00 01 00 00 58 28 ?? 02 00 06 28 ?? 02 00 06 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SXC_2147894263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SXC!MTB"
        threat_id = "2147894263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 16 2b 1e 11 16 6f ?? ?? ?? 0a 13 3c 11 11 11 3c 11 1f 59 61 13 11 11 1f 19 11 11 58 1e 63 59 13 1f 11 16 6f 3d 00 00 06 2d d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBEN_2147895357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBEN!MTB"
        threat_id = "2147895357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdddffhedfddffffgjfsfkdgsacsafp" ascii //weight: 1
        $x_1_2 = "sgfhjfffgdrfhddfhfffadfsfsscfgdb" ascii //weight: 1
        $x_1_3 = "djfsfhgdffafcfdssfkfhgj" ascii //weight: 1
        $x_1_4 = "ffchkffdahfdsfsfj" ascii //weight: 1
        $x_1_5 = "jhfdffdfdh" ascii //weight: 1
        $x_1_6 = "fdfcffrdgfdfsfsffj" ascii //weight: 1
        $x_1_7 = "jffffgfdsdfksdgkffff" ascii //weight: 1
        $x_1_8 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AAVW_2147895714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AAVW!MTB"
        threat_id = "2147895714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 02 8e 69 5d 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 0a 02 08 20 8e 10 00 00 58 20 8d 10 00 00 59 02 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 af}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AWKN_2147895975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AWKN!MTB"
        threat_id = "2147895975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHLN_2147895976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHLN!MTB"
        threat_id = "2147895976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 8e 69 5d 91 02 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AOR_2147896124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AOR!MTB"
        threat_id = "2147896124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0a 02 73 13 00 00 0a 0b 07 06 16 73 14 00 00 0a 0c 00 02 8e 69 8d 1e 00 00 01 0d 08 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 09 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "Check Car Form" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_UITT_2147896142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.UITT!MTB"
        threat_id = "2147896142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 18 00 00 0a 0b 73 30 00 00 0a 0d 00 20 98 3a 02 c9 25 13 04 13 05 16 13 0f 00 11 05 20 69 c5 fd 36 58 13 04 00 11 04 16 fe 01 16 fe 01 13 06 11 06 2d 03 16 2b 01 17 00 13 07 20 96 02 3d 9b 25 13 08 13 09 16 13 0f 00 11 09 20 6a fd c2 64 58 13 08 00 11 07 11 08 fe 01 13 0f 11 0f 2d 0f 00 06 09 7e 01 00 00 04 28 ?? ?? ?? 06 00 00 09 13 0a 20 8e f0 3a 8f 25 13 0b 13 0c 16 13 0f 00 11 0c 20 72 0f c5 70 58 13 0b 00 11 0a 11 0b 6a 6f ?? ?? ?? 0a 00 09 73 32 00 00 0a 13 0d 11 0d 28 ?? ?? ?? 06 0c 00 de 12 09 14 fe 01 13 0f 11 0f 2d 07 09 6f ?? ?? ?? 0a 00 dc 00 08 13 0e 2b 00 11 0e 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABLK_2147896449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABLK!MTB"
        threat_id = "2147896449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 11 09 03 11 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 11 06 11 09 11 07 5d 91 61 d2 9c 11 08 18 58 13 08 11 08 06 3f ?? ?? ?? ff 07 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "ToByte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABLS_2147896451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABLS!MTB"
        threat_id = "2147896451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 01 11 06 11 00 11 06 9a 1f 10 7e ?? ?? ?? 04 28 ?? ?? ?? 06 9c 20}  //weight: 3, accuracy: Low
        $x_1_2 = {6f 00 64 00 31 00 43 00 4a 00 58 00 72 00 73 00 6b 00 76 00 58 00 78 00 52 00 6e 00 54 00 66 00 58 00 37 00 2e 00 79 00 72 00 73 00 66 00 5a 00 74 00 32 00 75 00 44 00 53 00 46 00 38 00 46 00 4b 00 4f 00 55 00 32 00 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABUQ_2147896753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABUQ!MTB"
        threat_id = "2147896753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 0a 17 8d ?? 00 00 01 25 16 06 74 ?? 00 00 1b 28 ?? 00 00 06 a2 2a 2a 00 28 ?? 00 00 06 28 ?? 00 00 06 74 ?? 00 00 01 28}  //weight: 4, accuracy: Low
        $x_1_2 = "WindowsFormsApp76.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMBU_2147897167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMBU!MTB"
        threat_id = "2147897167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0a 07 11 0a 91 20 00 01 00 00 58 13 0b 07 11 09 91 13 0c 07 11 09 11 0c 08 11 08 1f 16 5d 91 61 11 0b 59 20 00 01 00 00 5d d2 9c 00 11 08 17 58 13 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMBB_2147897403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMBB!MTB"
        threat_id = "2147897403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 96 00 00 0a 13 04 07 11 04 14 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 7e ?? ?? ?? ?? 28 ?? 00 00 0a 14 14 14 14 6f ?? 00 00 0a 13 04 07 11 04 14}  //weight: 2, accuracy: Low
        $x_2_2 = "!@#@!@#@!##@!##@!##@!L!@#@!@#@!##@!##@!##@!oad!@#@!@#@!##@!##@!##@!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NBL_2147898269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NBL!MTB"
        threat_id = "2147898269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 6f 98 03 ?? ?? 08 07 5d 91 0d 0e 04 08 0e 05 58 03 08 04 58 91 02 6f 96 03 ?? ?? 09 06 5d 91 61 d2 9c 08 17 58 0c 08 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMBG_2147898294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMBG!MTB"
        threat_id = "2147898294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 18 14 6f ?? 00 00 0a 72 ?? 02 00 70 18 14 6f ?? 00 00 0a 72 ?? 02 00 70 18 17 8d ?? 01 00 01 25 16 7e ?? 00 00 04 6f ?? 00 00 0a a2 6f ?? 00 00 0a 72 ?? 02 00 70 18 14 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMBE_2147898426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMBE!MTB"
        threat_id = "2147898426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 04 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 00 02 03 05 28 ?? 00 00 06 0b 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASGC_2147898629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASGC!MTB"
        threat_id = "2147898629"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 16 11 00 8e 69 28 ?? 00 00 0a 20 01 00 00 00 7e ?? 1e 00 04 7b ?? 1e 00 04 3a ?? ff ff ff 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASGC_2147898629_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASGC!MTB"
        threat_id = "2147898629"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0c 08 11 0a 91 61 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 11}  //weight: 1, accuracy: High
        $x_1_2 = {07 11 09 91 13 0c 20 00 01 00 00 13 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AP_2147898933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AP!MTB"
        threat_id = "2147898933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 08 11 04 16 73 ?? 02 00 0a 0d 09 07 6f ?? 02 00 0a 07 6f ?? 02 00 0a 13 05 de 1f 09 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NL_2147898973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NL!MTB"
        threat_id = "2147898973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 6f 0d ?? ?? ?? 03 58 20 00 ?? ?? ?? 5d 0c 08 16 2f 08 08 20 00 ?? ?? ?? 58 0c 06 07 08 d1 9d 07 17 58 0b 07 02 6f 0c ?? ?? ?? 32 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RSH_2147899246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RSH!MTB"
        threat_id = "2147899246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 88 00 00 0a 74 30 00 00 01 72 3e 05 00 70 72 42 05 00 70 6f 8c 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {17 00 08 11 05 07 11 05 9a 1f 10 28 8e 00 00 0a 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RSY_2147899247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RSY!MTB"
        threat_id = "2147899247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0f 00 00 06 28 01 00 00 2b 28 02 00 00 2b 0a de 03 26 de ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_FV_2147899396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.FV!MTB"
        threat_id = "2147899396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 1b 00 7e ?? ?? ?? 04 06 7e ?? ?? ?? 04 06 91 20 74 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? ?? 04 8e 69 fe 04 0b 07 2d d7}  //weight: 1, accuracy: Low
        $x_1_2 = "cdn.discordapp.com/attachments/" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDK_2147900021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDK!MTB"
        threat_id = "2147900021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 26 0a 06 28 10 00 00 0a 25 26 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDL_2147901707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDL!MTB"
        threat_id = "2147901707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 86 00 00 0a 0d 09 28 01 00 00 2b 28 02 00 00 2b 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KAAI_2147901708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KAAI!MTB"
        threat_id = "2147901708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 34 00 30}  //weight: 1, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SPCC_2147901821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SPCC!MTB"
        threat_id = "2147901821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0b 11 0f 11 0b 8e 69 5d 91 61 d2 52 00 11 0f 17 58 13 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMBA_2147902154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMBA!MTB"
        threat_id = "2147902154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {04 06 25 0b 6f ?? 00 00 0a 00 07 0c 2b 00 08 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KAAJ_2147902199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KAAJ!MTB"
        threat_id = "2147902199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 07 11 ?? 17 58 ?? ?? ?? ?? ?? 5d 91 08 58 08 5d 59 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MAQ_2147902515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MAQ!MTB"
        threat_id = "2147902515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 40 01 00 0a 13 06 02 73 41 01 00 0a 13 07 11 07 74 ?? ?? ?? 01 11 06 75 ?? ?? ?? 01 16 73 42 01 00 0a 13 08 1a 13 14 2b a8 02 8e 69 17 da 17 d6 8d ?? ?? ?? 01 13 09 11 08 75 b9 00 00 01 11 09 75 09 00 00 1b 16 11 09 75 09 00 00 1b 8e 69 6f 43 ?? ?? ?? 13 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMBC_2147902772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMBC!MTB"
        threat_id = "2147902772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 04 0e 08 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {04 06 25 0b 6f ?? 00 00 0a 00 07 0c 2b 00 08 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SMTN_2147902880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SMTN!MTB"
        threat_id = "2147902880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 05 5a 13 04 11 05 17 58 13 05 11 05 02 31 ee}  //weight: 1, accuracy: High
        $x_1_2 = {08 09 58 0c 09 17 58 0d 09 02 31 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PADP_2147903013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PADP!MTB"
        threat_id = "2147903013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 07 08 11 07 91 20 7e 06 00 00 59 d2 9c 00 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SPJJ_2147903230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SPJJ!MTB"
        threat_id = "2147903230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0c de 19 07 2c 06}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MVA_2147903546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MVA!MTB"
        threat_id = "2147903546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 28 08 00 00 0a 08 28 09 00 00 0a 0d}  //weight: 1, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GIAA_2147904040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GIAA!MTB"
        threat_id = "2147904040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 25 00 7e ?? 00 00 04 07 7e ?? 00 00 04 07 91 17 8d ?? 00 00 01 25 16 1f 5d 9c 07 17 5d 91 61 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe 04 0c 08 2d cd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDM_2147904060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDM!MTB"
        threat_id = "2147904060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {59 20 00 00 01 00 58 20 00 00 01 00 5d 13 04 06 11 04 d1 13 05 12 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMMB_2147904265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMMB!MTB"
        threat_id = "2147904265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 05 0e 07 0e 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 00 02 03 02 03 02 02 03 05 28 ?? 00 00 06 0a 2b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GQAA_2147904370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GQAA!MTB"
        threat_id = "2147904370"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 13 00 06 09 06 09 91 20 ?? ?? 00 00 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SPCP_2147904779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SPCP!MTB"
        threat_id = "2147904779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 0d 06 11 0d 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 0d 17 58 13 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SPDF_2147905343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SPDF!MTB"
        threat_id = "2147905343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 10 07 11 0c 11 10 d2 9c}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KAAL_2147905526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KAAL!MTB"
        threat_id = "2147905526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 07 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 16 fe 01 13 04 11 04 2c 02 16 0b 00 08 17 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMMD_2147905912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMMD!MTB"
        threat_id = "2147905912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 58 09 5d 91 13 [0-30] 59 20 00 01 00 00 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KAAM_2147906226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KAAM!MTB"
        threat_id = "2147906226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 03 6f ?? 00 00 0a 25 04 6f ?? 00 00 0a 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 10 00 02 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_JWAA_2147906773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.JWAA!MTB"
        threat_id = "2147906773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0b 11 0c 91 07 11 07 17 58 11 06 5d 91 13 0d 08 11 07 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 13 0e 11 0e 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SYU_2147907050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SYU!MTB"
        threat_id = "2147907050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 09 06 8e 69 5d 1f 1d 59 1f 1d 58 06 09 06 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 91 08 09 08 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 91 61 06 09 20 8a 10 00 00 58 20 89 10 00 00 59 06 8e 69 5d 1f 09 58 1f 0f 58 1f 18 59 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 09 17 58 0d 09 6a 06 8e 69 17 59 6a 07 17 58 6e 5a 31 93}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KBAA_2147907051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KBAA!MTB"
        threat_id = "2147907051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 1c 13 08 38 ?? ff ff ff 08 74 ?? 00 00 01 03 6f ?? 00 00 0a 08 74 ?? 00 00 01 6f ?? 00 00 0a 13 04}  //weight: 2, accuracy: Low
        $x_2_2 = {01 02 16 02 8e 69 6f ?? 00 00 0a de 49}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MVR_2147908914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MVR!MTB"
        threat_id = "2147908914"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 72 29 00 00 70 6f 05 00 00 0a 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDN_2147910220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDN!MTB"
        threat_id = "2147910220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {91 11 06 11 06 09 95 11 06 11 04 95 58 20 ff 00 00 00 5f 95 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SKJ_2147910234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SKJ!MTB"
        threat_id = "2147910234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://groundbreakingsstyle.com/wp-content/nanofolder/img-files/VFLient.vas" ascii //weight: 1
        $x_1_2 = "OxyPlotting.EWGibraltar" ascii //weight: 1
        $x_1_3 = "dTYyYVg0NlRhN3A3ZmhhdEltT0Y1bmVxMXJiYWVPV2M=" ascii //weight: 1
        $x_1_4 = "a05Icks5elhwSzUydE9VVw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SKI_2147910235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SKI!MTB"
        threat_id = "2147910235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 03 06 07 04 28 32 00 00 06 00 00 07 17 58 0b 07 02 28 30 00 00 06 2f 0b 03 6f 96 00 00 0a 04 fe 04 2b 01 16 0c 08 2d d6}  //weight: 1, accuracy: High
        $x_1_2 = "$58edd536-1aca-4346-97ce-d606b3111f51" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SKI_2147910235_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SKI!MTB"
        threat_id = "2147910235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Administrator\\Desktop\\Outputs\\YgZBrsLNe.pdb" ascii //weight: 1
        $x_1_2 = "2mGLLPucVX9eYQeGwiNRuX84JPX3T2FvJoutbylz3IgZD0tS3A0yJzWe" ascii //weight: 1
        $x_1_3 = "OxyPlotting.EWGibraltar" ascii //weight: 1
        $x_1_4 = "BundleSharp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDO_2147910346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDO!MTB"
        threat_id = "2147910346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 06 6f 17 00 00 0a 16 73 18 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SUJ_2147911668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SUJ!MTB"
        threat_id = "2147911668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 02 6f 89 00 00 0a 18 5b 8d 76 00 00 01 0a 16 0b 2b 1a 00 06 07 02 07 18 5a 18 [0-5] 1f 10 28 8b 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc}  //weight: 1, accuracy: Low
        $x_1_2 = "AsnanyDentalClinic.Properties" ascii //weight: 1
        $x_1_3 = "Bitmap" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "Split" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASEK_2147912162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASEK!MTB"
        threat_id = "2147912162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 09 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RP_2147912704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RP!MTB"
        threat_id = "2147912704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 05 59 08 8e 69 59 13 07 11 07 8d ?? 00 00 01 13 08 07 11 05 08 8e 69 58 11 08 16 11 07 28 ?? 00 00 0a 00 11 08 13 15 2b 00 11 15 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KAAQ_2147914187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KAAQ!!MTB"
        threat_id = "2147914187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {95 11 09 11 07 95 58 20 ff 00 00 00 5f 95 61 d2 9c 00 11 10 17 6a 58 13 10}  //weight: 1, accuracy: High
        $x_1_2 = "55CA5DACB0EE949F43" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KAAR_2147914276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KAAR!MTB"
        threat_id = "2147914276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 11 ?? 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 11 ?? 5d 13 ?? 11 ?? 11 ?? 91 13 ?? 11 ?? 11 ?? 59 13 0e 20 ff 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMMH_2147915076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMMH!MTB"
        threat_id = "2147915076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 [0-32] 17 58 08 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMMI_2147915077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMMI!MTB"
        threat_id = "2147915077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 [0-25] 8e 69 5d 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NG_2147915618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NG!MTB"
        threat_id = "2147915618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 03 4b 04 4b 61 1f 7b 58 0a 03 4b 0b 03 04 4b 54 04 07 54}  //weight: 1, accuracy: High
        $x_1_2 = {5f 0a 06 16 fe 01 0c 08 2c 04 00 17 0a 00}  //weight: 1, accuracy: High
        $x_2_3 = "3dad2be1-d9c2-4843-b189-063c10458dd7" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NG_2147915618_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NG!MTB"
        threat_id = "2147915618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 20 61 11 18 19 58 61 11 32 61 d2 9c}  //weight: 2, accuracy: High
        $x_2_2 = {58 1d 11 20 58 61 d2 13 18 11 21 16 91 11 21 18 91 1e 62 60 11 18 19 62 58}  //weight: 2, accuracy: High
        $x_2_3 = {13 22 11 0d 11 22 11 0f 59 61 13 0d 11 0f 11 0d 19 58 1e 63 59}  //weight: 2, accuracy: High
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASKL_2147915646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASKL!MTB"
        threat_id = "2147915646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {58 d2 13 11 11 06 11 11 20 ff 00 00 00 5f 95 d2 13 12 11 10 11 12 61 13 13 11 07 11 0f d4 11 13 20 ff 00 00 00 5f d2 9c 00 11 0f 17 6a 58 13 0f 11 0f 11 07 8e 69 17 59 6a fe 02 16 fe 01}  //weight: 4, accuracy: High
        $x_1_2 = "524OZ4CTQ7ZJ8GE7I7C8JA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDP_2147915967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDP!MTB"
        threat_id = "2147915967"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a2 28 bd 00 00 0a 75 33 00 00 01 0b 07 6f be 00 00 0a 18 9a 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAP_2147916325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAP!MTB"
        threat_id = "2147916325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 04 11 05 02 08 11 05 58 91 03 11 05 07 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 09 fe 04 13 06 11 06 2d}  //weight: 3, accuracy: High
        $x_1_2 = "GetBytesAsync" ascii //weight: 1
        $x_1_3 = "schtasks /create /tn \"Alis Cloud\" /tr \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAR_2147916535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAR!MTB"
        threat_id = "2147916535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 0a 16 0b 2b ?? 00 02 07 7e ?? 00 00 04 07 91 03 07 06 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe ?? 0c 08 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDQ_2147916578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDQ!MTB"
        threat_id = "2147916578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 27 00 00 0a 6f 28 00 00 0a 0b 73 29 00 00 0a 0c 08 07 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDR_2147916833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDR!MTB"
        threat_id = "2147916833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 08 5d 08 58 08 5d 91 11 07 61 11 09 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NM_2147916867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NM!MTB"
        threat_id = "2147916867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 8e 69 18 da 0b 73 46 00 00 0a 0c 07 0d 16 13 04}  //weight: 5, accuracy: High
        $x_1_2 = "w124728_New_Text_Document.txt" ascii //weight: 1
        $x_1_3 = "https://imgurl.ir/download.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAU_2147916900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAU!MTB"
        threat_id = "2147916900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d4 91 09 09 07 95 09 11 ?? 95 58 20 ff 00 00 00 5f 95 d2 61 d2 9c 11 ?? 17 6a 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GNK_2147917085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GNK!MTB"
        threat_id = "2147917085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 11 59 17 58 8d ?? ?? ?? 01 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 28 ?? ?? ?? 0a 11 04 13 05 dd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SML_2147917322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SML!MTB"
        threat_id = "2147917322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project_Calendar.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "$36031fe2-536e-44b7-ae4d-1f680f68032f" ascii //weight: 1
        $x_1_3 = "G5ZPEF865HC88G0GCD4GD0" ascii //weight: 1
        $x_1_4 = "Bitmap" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_TGAA_2147917674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.TGAA!MTB"
        threat_id = "2147917674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 02 08 20 0d 02 00 00 58 20 0c 02 00 00 59 1d 59 1d 58 02 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SAA_2147917733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SAA!MTB"
        threat_id = "2147917733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 28 0e 00 00 06 0d 7e 05 00 00 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SPDG_2147918667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SPDG!MTB"
        threat_id = "2147918667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 d1 13 14 11 1d 11 09 91 13 22 11 1d 11 09 11 21 11 22 61 11 1f 19 58 61 11 34 61 d2 9c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KAAY_2147918743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KAAY!MTB"
        threat_id = "2147918743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 5d 08 58 [0-8] 5d [0-15] 61 ?? ?? 59 20 00 02 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ASI_2147918822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ASI!MTB"
        threat_id = "2147918822"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 07 73 ?? 00 00 0a 13 05 11 05 09 16 73 ?? 00 00 0a 13 06 11 06 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 07 de 43}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SLA_2147919116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SLA!MTB"
        threat_id = "2147919116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 11 00 00 06 0a 72 41 01 00 70 0b 73 56 00 00 0a 25 72 c6 01 00 70 6f 57 00 00 0a 00 25 72 08 02 00 70 6f 58 00 00 0a 00 0c 07 08 28 59 00 00 0a 6f 5a 00 00 0a 0d 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NJ_2147919211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NJ!MTB"
        threat_id = "2147919211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 03 8e 69 18 da 0b 73 ?? 00 00 0a 0c 07 0d 16}  //weight: 2, accuracy: Low
        $x_2_2 = {11 04 19 32 0a 11 04 1b fe 02 16 fe 01}  //weight: 2, accuracy: High
        $x_2_3 = {06 9a 08 06 19 da 07 d8}  //weight: 2, accuracy: High
        $x_2_4 = "https://imgurl.ir/download.php" ascii //weight: 2
        $x_1_5 = "ReadAsStringAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SUPF_2147919758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SUPF!MTB"
        threat_id = "2147919758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 05 11 06 6f ?? ?? ?? 0a 13 07 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 20 00 1e 01 00 fe 04 13 08 11 08 2c 0e 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 20 00 1e 01 00 fe 04 13 09 11 09 2c 0e 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 11 06 17 58 13 06 11 06 07 6f ?? ?? ?? 0a fe 04 13 0a 11 0a 2d 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBXT_2147920048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBXT!MTB"
        threat_id = "2147920048"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4c 00 6f 00 61 00 64 [0-8] 44 00 75 00 6d 00 6d 00 79 00 43 00 70 00 70 00 43 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 72}  //weight: 3, accuracy: Low
        $x_2_2 = "Split" ascii //weight: 2
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAI_2147920114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAI!MTB"
        threat_id = "2147920114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 17 58 20 ff 00 00 00 5f 0d [0-10] 09 95 58 20 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_2_2 = {95 16 61 d2 13 [0-15] 61 16 60 d2 13 [0-20] 20 ff 00 00 00 5f d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KAAZ_2147920234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KAAZ!MTB"
        threat_id = "2147920234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 d7 20 ff 00 00 00 5f [0-50] 95 d7 20 ff 00 00 00 5f 95 61 86 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PWH_2147920670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PWH!MTB"
        threat_id = "2147920670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 73 43 00 00 0a 0b 07 72 61 00 00 70 28 ?? ?? ?? 0a 72 93 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 73 46 00 00 0a 0d 09 08 17 73 47 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 0a dd 0f 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBXW_2147921640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBXW!MTB"
        threat_id = "2147921640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 09 09 11 05 07 11 05 91 11 04 11 09 95 61 28 ?? 00 00 0a 9c 11 05 17 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NC_2147922731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NC!MTB"
        threat_id = "2147922731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ac6d2d7f-d38f-4bfc-a687-916008002e71" ascii //weight: 3
        $x_1_2 = {0d 09 18 5b 13 04 11 04 18 5a 13 05 11 05 09 fe 01 13 09 11 09}  //weight: 1, accuracy: High
        $x_1_3 = {09 16 31 07 11 07 16 fe 03 2b 01 16 13 0a 11 0a 2c 0a 03 11 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ND_2147922732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ND!MTB"
        threat_id = "2147922732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 16 02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 24 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 ?? 00 00 06 58 54 2a}  //weight: 1, accuracy: Low
        $x_3_2 = "d7b3666c-8497-4269-8d3f-22cca874bba8" ascii //weight: 3
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DownloadDataAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMJ_2147922801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMJ!MTB"
        threat_id = "2147922801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 07 6f ?? 00 00 0a 0c 2b 29 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PPH_2147923241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PPH!MTB"
        threat_id = "2147923241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 13 06 2b 42 07 11 05 11 06 6f ?? 00 00 0a 13 07 08 6f ?? 00 00 0a 19 58 09 30 0a 08 11 07 28 ?? 00 00 06 2b 1b 09 08 6f ?? 00 00 0a 59 13 08 11 08 16 31 1c 08 11 07 11 08 28 ?? 00 00 06 2b 10 11 06 17 58 13 06 11 06 07 6f ?? 00 00 0a 32 b4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PPE_2147923506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PPE!MTB"
        threat_id = "2147923506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 11 06 07 11 06 91 11 04 11 11 95 61 28 ?? 00 00 0a 9c 11 06 17 58 13 06}  //weight: 3, accuracy: Low
        $x_2_2 = {00 11 09 17 58 20 ff 00 00 00 5f 13 09 11 07 11 04 11 09 95 58 20 ff 00 00 00 5f 13 07 02 11 04 11 09 8f 40 00 00 01 11 04 11 07 8f 40 00 00 01 28 ?? 00 00 06 00 11 04 11 09 95 11 04 11 07 95 58 20 ff 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BE_2147923656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BE!MTB"
        threat_id = "2147923656"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {95 58 20 ff 00 00 00 5f 13 0e 11 05 13 0f 07 11 0f 91 13 10 11 04 11 0e 95 13 11 11 10 11 11 61 13 12 09 11 0f 11 12 d2 9c 11 05 17 58 13 05 00 11 05 6e 09 8e 69 6a fe 04 13 13 11 13 2d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZVAA_2147923903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZVAA!MTB"
        threat_id = "2147923903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 1f fd 5f 09 fe 01 13 04 11 04 2c 37 00 03 19 8d ?? 00 00 01 25 16}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 13 06 19 8d ?? 00 00 01 25 17 17 9e 25 18 18 9e 13 07 16 13 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBXV_2147923990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBXV!MTB"
        threat_id = "2147923990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 6a 5d d4 91 58 11 ?? 11 ?? 95 58 20 ?? 00 00 00 5f}  //weight: 2, accuracy: Low
        $x_1_2 = "V88G54KE8I58HT058BHQEA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVB_2147924270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVB!MTB"
        threat_id = "2147924270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 19 11 17 d4 11 4a 6e 11 4d 20 ff 00 00 00 5f 6a 61 d2 9c 11 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_KABA_2147924322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.KABA!MTB"
        threat_id = "2147924322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {19 59 91 08 09 08 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 1c 58 1c 59 91 61 06 09 20 11 02 00 00 58 20 10 02 00 00 59 06 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 1c 58 1c 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SCCF_2147924467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SCCF!MTB"
        threat_id = "2147924467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {04 08 03 08 91 05 09 95 61 d2 9c 00 08 17 58 0c 08 03 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SCCF_2147924467_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SCCF!MTB"
        threat_id = "2147924467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 04 28 ?? 00 00 2b 05 28 ?? 00 00 2b 6f ?? 00 00 0a 0b 07 03 28 ?? 00 00 2b 16 03 28 ?? 00 00 2b 6f ?? 00 00 0a 0c de 14 07 2c 06}  //weight: 3, accuracy: Low
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMU_2147924638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMU!MTB"
        threat_id = "2147924638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {06 17 58 20 ff 00 00 00 5f 0a 07 05 06 95 58 20 ff 00 00 00 5f 0b 02 05 06}  //weight: 4, accuracy: High
        $x_1_2 = {58 20 00 01 00 00 5e 26 04 08 03 08 91 05 09 95 61 d2 9c 08 17 58 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMV_2147924734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMV!MTB"
        threat_id = "2147924734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 04 28 ?? 00 00 2b 05 28 ?? 00 00 2b 6f ?? 00 00 0a 0b 07 03 28 ?? 00 00 2b 16 03 28 ?? 00 00 2b 6f ?? 00 00 0a 0c de 14}  //weight: 4, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NF_2147925556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NF!MTB"
        threat_id = "2147925556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 26 04 08 03 08 91 05 09 95 61 d2 9c 08 17 58 0c 08 03 8e 69}  //weight: 1, accuracy: High
        $x_2_2 = "cae19f42-366b-4fad-b842-1d6898b0731a" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NI_2147925558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NI!MTB"
        threat_id = "2147925558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 08 17 59 13 08 02 7b 33 01 00 04 11 04 7b 02 00 00 04 11 09 9e 14 13 04 2b 21 11 06 11 04}  //weight: 1, accuracy: High
        $x_2_2 = "fb078dbd-b988-40b9-b8b0-9272c73f6ee3" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BH_2147925597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BH!MTB"
        threat_id = "2147925597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 06 16 73 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 20 00 04 00 00 8d ?? 00 00 01 13 04 2b 0b 09 11 04 16 11 05 6f ?? 00 00 0a 08 11 04 16 11 04 8e 69 6f ?? 00 00 0a 25 13 05 16 30}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RDS_2147925861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RDS!MTB"
        threat_id = "2147925861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 07 11 07 06 16 06 8e 69 6f 25 00 00 0a 11 06 6f 26 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SKF_2147925908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SKF!MTB"
        threat_id = "2147925908"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 02 03 06 04 28 42 00 00 06 00 00 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0b 07 2d d7}  //weight: 1, accuracy: Low
        $x_1_2 = "$db97782b-197a-4335-868a-51ae9ee87ebc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAC_2147925924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAC!MTB"
        threat_id = "2147925924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 11 04 08 09 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 06 16 06 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 0b dd}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ADK_2147926227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ADK!MTB"
        threat_id = "2147926227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 06 2b 41 17 13 07 16 13 08 2b 1d 07 11 06 11 08 58 91 06 11 08 6f ?? 00 00 0a d2 2e 05 16 13 07 2b 10 11 08 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = {09 13 0a 2b 11 11 05 11 0a 09 59 07 11 0a 91 9c 11 0a 17 58 13 0a 11 0a 11 04 32 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMX_2147926298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMX!MTB"
        threat_id = "2147926298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 06 04 6f ?? 00 00 0a 00 06 05 6f ?? 00 00 0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 07 03 16 03 8e 69 6f ?? 00 00 0a 0c 2b 00 08 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMY_2147926299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMY!MTB"
        threat_id = "2147926299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 20 00 01 00 00 14 14 14 6f ?? ?? 00 0a 26 20 00 00 00 00 7e}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AODA_2147926344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AODA!MTB"
        threat_id = "2147926344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 7e ?? 03 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 03 00 06 03 08 1e 58 1d 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 15 2c 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SKM_2147926484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SKM!MTB"
        threat_id = "2147926484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 02 03 06 04 28 42 00 00 06 00 00 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0b 07 2d d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AYDA_2147926626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AYDA!MTB"
        threat_id = "2147926626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0e 05 1f 7b 61 20 ff 00 00 00 5f 20 c8 01 00 00 58 20 00 01 00 00 5e 26 05 03 04 03 91 0e 04 0e 05 95 61 d2 9c 2a}  //weight: 4, accuracy: High
        $x_1_2 = "HEHZ6G78G7B4GFD8EE8A79" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AMAE_2147926642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AMAE!MTB"
        threat_id = "2147926642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 20 ff 00 00 00 5f [0-15] 58 20 00 01 00 00 5e [0-30] 05 03 04 03 91 0e ?? 0e ?? 95 61 d2 9c 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AYA_2147926811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AYA!MTB"
        threat_id = "2147926811"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2023CryptsDone\\drwk" ascii //weight: 2
        $x_1_2 = "files will be deleted permanently. Proceed?" wide //weight: 1
        $x_1_3 = "exporterWorker_RunWorkerCompleted" ascii //weight: 1
        $x_1_4 = "lameExeDownloadSite" ascii //weight: 1
        $x_1_5 = "dupeFinderWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PPLH_2147927036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PPLH!MTB"
        threat_id = "2147927036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {1f 10 62 12 00 28 ?? ?? ?? ?? 1e 62 60 12 00 28 ?? ?? ?? ?? 60 0d 03 09 1f 10 63 20 ff 00 00 00 5f d2 6f ?? ?? ?? ?? 00 03 09 1e 63}  //weight: 6, accuracy: Low
        $x_5_2 = {9c 25 17 12 00 28 ?? ?? ?? ?? 9c 25 18 12 00 28 ?? ?? ?? ?? 9c 07 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 00 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BJ_2147927099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BJ!MTB"
        threat_id = "2147927099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {35 00 46 00 34 00 33 00 36 00 46 00 37 00 32 00 34 00 34 00 36 00 43 00 36 00 43 00 34 00 44 00 36 00 31 00 36 00 39 00 36 00 45 00 5f 00 36 00 44 00 37 00 33 00 36 00 33 00 36 00 46 00 37 00 32 00 36 00 35 00 36 00 35 00 32 00 45 00 36 00 34 00 36 00 43 00 36 00 43}  //weight: 3, accuracy: High
        $x_2_2 = {32 00 45 00 36 00 38 00 45 00 45 00 38 00 32 00 38 00 46 00 37 00 34 00 36 00 46 00 36 00 33 00 41 00 35 00 37 00 38 00 31 00 34 00 37 00 38 00 43 00 38 00 38 00 34 00 30 00 38 00 30 00 32 00 43 00 37 00 38 00 43 00 46 00 41 00 46 00 46 00 42 00 45 00 39 00 30 00 45 00 42 00 36 00 43 00 35 00 30 00 41 00 34 00 46 00 37 00 41 00 33 00 46 00 39 00 42 00 45 00 46 00 32 00 37 00 38 00 37 00 31 00 43 00 36}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_APEA_2147927114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.APEA!MTB"
        threat_id = "2147927114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 2b 25 72 ?? ?? 00 70 2b 21 2b 26 2b 2b 72 ?? ?? 00 70 2b 27 2b 2c 2b 31 2b 32 06 16 06 8e 69 6f ?? 00 00 0a 0c de 45 07 2b d8 28 ?? ?? 00 0a 2b d8 6f ?? 00 00 0a 2b d3 07 2b d2 28 ?? ?? 00 0a 2b d2 6f ?? ?? 00 0a 2b cd 07 2b cc 6f ?? ?? 00 0a 2b c7}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBWD_2147927279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBWD!MTB"
        threat_id = "2147927279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 1f 2a 5a 58 0a 00 07 17 58 0b 07 1b fe 04 0c 08 2d eb}  //weight: 2, accuracy: High
        $x_1_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AUEA_2147927386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AUEA!MTB"
        threat_id = "2147927386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {60 0d 03 19 8d ?? 00 00 01 25 16 09 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 09 1e 63 20 ff 00 00 00 5f d2 9c 25 18 09 20 ff 00 00 00 5f d2 9c}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 04 28 ?? 00 00 2b 6f ?? 00 00 0a 00 2a}  //weight: 2, accuracy: Low
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NR_2147927971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NR!MTB"
        threat_id = "2147927971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {72 40 1e 00 70 0a 06 28 ad 01 00 06 72 c5 1e 00 70 28 61 01 00 0a 28 29 00 00 2b 0b 73 36 00 00 06 07 28 47 00 00 06 28 2f 00 00 0a 0c 73 45 01 00 06 28 63 01 00 0a}  //weight: 3, accuracy: High
        $x_2_2 = {25 13 08 28 72 00 00 0a 13 09 11 08 16 91 2d 02 2b 1f 11 07 16 9a 28 2f 00 00 0a d0 59 00 00 01 28 32 00 00 0a 28 d6 00 00 0a a5 59 00 00 01 10 04 11 09 14 72 a3 03 00 70 16 8d 04 00 00 01 14 14 14 28 72 00 00 0a 28 2f 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PKSH_2147928290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PKSH!MTB"
        threat_id = "2147928290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 03 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0a de 09}  //weight: 8, accuracy: Low
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVD_2147928497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVD!MTB"
        threat_id = "2147928497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5e 00 00 00 19 00 00 00 fe 00 00 00 93 00 00 00 ab 00 00 00 90 00 00 00 17 00 00 00 1e 00 00 00 02 00 00 00 05 00 00 00 06 00 00 00 05 00 00 00 01 00 00 00 06 00 00 00 14 00 00 00 02 00 00 00 03}  //weight: 1, accuracy: High
        $x_1_2 = "bc2029aa-e32f-4633-80cd-24e894239c0f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PKWH_2147928500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PKWH!MTB"
        threat_id = "2147928500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {04 12 04 28 ?? 00 00 0a 1f 10 62 12 04 28 ?? 00 00 0a 1e 62 60 12 04 28 ?? 00 00 0a 60 13 09 08 25 7b ?? 00 00 04 11 09}  //weight: 6, accuracy: Low
        $x_5_2 = {25 16 11 09 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 11 09 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 11 09 20 ?? 00 00 00 5f d2 9c 6f ?? 00 00 0a 00 08 25 7b ?? 00 00 04 08 7b ?? 00 00 04 6a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBWI_2147929038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBWI!MTB"
        threat_id = "2147929038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 2b 37 02 28 ?? 00 00 0a 0b 12 01 28 ?? 00 00 0a 17 58 20 00 01 00 00 5d 02 28 ?? 00 00 0a 0b 12 01 28 ?? 00 00 0a 02}  //weight: 2, accuracy: Low
        $x_1_2 = "pwsgl3.Properti" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AOHA_2147929213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AOHA!MTB"
        threat_id = "2147929213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 11 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 08 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 08 20 ff 00 00 00 5f d2 9c}  //weight: 4, accuracy: High
        $x_2_2 = {01 25 16 12 05 28 ?? 00 00 0a 9c 25 17 12 05 28 ?? 00 00 0a 9c 25 18 12 05 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PLICH_2147931102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PLICH!MTB"
        threat_id = "2147931102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 62 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0d 02 19 8d ?? 00 00 01 25 16 09 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 09 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 09 20 ?? 00 00 00 5f d2 9c 6f ?? 00 00 0a 06 09 5a 16}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PLIHH_2147931391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PLIHH!MTB"
        threat_id = "2147931391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 02 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 02 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 02 20 ?? 00 00 00 5f d2 9c 2a}  //weight: 6, accuracy: Low
        $x_5_2 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_NCF_2147931929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.NCF!MTB"
        threat_id = "2147931929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {03 19 8d 3b 00 00 01 25 16 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 06 20 ff 00 00 00 5f d2 9c 6f 48 00 00 0a 00 2a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BA_2147932663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BA!MTB"
        threat_id = "2147932663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 06 08 91 03 08 03 6f 05 00 00 0a 5d 6f 06 00 00 0a 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_CLZ_2147934087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.CLZ!MTB"
        threat_id = "2147934087"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 3c 00 00 06 0c 72 7a 02 00 70 28 51 00 00 0a 0d 72 ac 02 00 70 28 51 00 00 0a 13 04 73 52 00 00 0a 13 05 73 41 00 00 0a 13 06 11 06 11 05 09 11 04 6f 53 00 00 0a 17 73 54 00 00 0a 13 07 2b 16 2b 18 16 2b 18 8e 69 2b 17 17 16 2c 1a 26 2b 1a 2b 1c 13 08 de 70 11 07 2b e6 08 2b e5 08 2b e5 6f ?? 00 00 0a 2b e2 0b 2b e4 11 06 2b e2 6f ?? 00 00 0a 2b dd 11 07 2c 0a 16 2d 07 11 07 6f 38 00 00 0a 18 2c f3 dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BB_2147934264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BB!MTB"
        threat_id = "2147934264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0c 06 00 fe 0c 03 00 fe 0c 05 00 94 58 fe 0c 04 00 fe 0c 05 00 94 58 28 6b 00 00 06 28 50 00 00 0a 5d fe 0e 06 00 fe 0c 03 00 fe 0c 05 00 94 fe 0e 0b 00 fe 0c 03 00 fe 0c 05 00 fe 0c 03 00 fe 0c 06 00 94 9e fe 0c 03 00 fe 0c 06 00 fe 0c 0b 00 9e fe 0c 05 00 20 01 00 00 00 58 fe 0e 05 00 fe 0c 05 00 28 6c 00 00 06 28 50 00 00 0a 3f 8c ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ADN_2147934503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ADN!MTB"
        threat_id = "2147934503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "UEkSEzUJmmfNQVp" wide //weight: 3
        $x_2_2 = "zCom.resources" wide //weight: 2
        $x_2_3 = "byvodDQbkPUtmBt" wide //weight: 2
        $x_1_4 = "MdhRNwaxhLoQXgo" wide //weight: 1
        $x_1_5 = "BRDDSJWxWuzlOSG" wide //weight: 1
        $x_2_6 = "UyxfVYIeTPViEHR" wide //weight: 2
        $x_3_7 = "hJfdFcDnErRGOwB" wide //weight: 3
        $x_1_8 = "xHhirgYXjrfAYps" wide //weight: 1
        $x_2_9 = "KskmgZrteiTAKvP" wide //weight: 2
        $x_3_10 = "ONryVvSRgCBlXMf" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BN_2147934686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BN!MTB"
        threat_id = "2147934686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5d 9e 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0b 16 0c 2b}  //weight: 4, accuracy: Low
        $x_1_2 = {06 08 06 08 94 18 5a 1f 64 5d 9e 08 17 58 0c 08 03 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVE_2147935128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVE!MTB"
        threat_id = "2147935128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 a2 29 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 77 00 00 00 14 00 00 00 65 00 00 00 77 00 00 00 65 00 00 00 0f 01 00 00 6c 00 00 00 01 00 00 00 24 00 00 00 08 00 00 00 1c 00 00 00 2a 00 00 00 26 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 03 00 00 00 06 00 00 00 0a 00 00 00 12}  //weight: 1, accuracy: High
        $x_1_2 = "ToDoList.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVE_2147935128_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVE!MTB"
        threat_id = "2147935128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 7b 00 00 00 0d 00 00 00 86 00 00 00 77 00 00 00 71 00 00 00 e7 00 00 00 20 00 00 00 20 00 00 00 03 00 00 00 06 00 00 00 07 00 00 00 12 00 00 00 01 00 00 00 06 00 00 00 07 00 00 00 02 00 00 00 02 00 00 00 09}  //weight: 1, accuracy: High
        $x_1_2 = "5c783933-7df2-43c6-86c5-f4edbdd9a369" ascii //weight: 1
        $x_1_3 = "Projektni_zadatak.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBV_2147935187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBV!MTB"
        threat_id = "2147935187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 06 1f 28 5a 58 13 07 11 07}  //weight: 1, accuracy: High
        $x_2_2 = {45 50 78 00 4e 37 6f 37 73 34 4d 33 56 57 34 55 53 66 74 76 47 45 00 45 39 6f 31 35 77 69 44 6b 6f 48 66 45 79 66 31 5a 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MBU_2147935188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MBU!MTB"
        threat_id = "2147935188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 12 00 28 ?? 00 00 0a 1f 0a 5d 03 1f 0a 5a 04 58 6f ?? 00 00 0a 06 07 05}  //weight: 2, accuracy: Low
        $x_1_2 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SWA_2147935632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SWA!MTB"
        threat_id = "2147935632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 13 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 11 07 08 16 08 8e 69 6f ?? 00 00 0a 17 0b 11 06 6f ?? 00 00 0a 13 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BO_2147935688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BO!MTB"
        threat_id = "2147935688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 19 fe 04 16 fe 01 0c 08 2c 0c 00 02 04 28 ?? 00 00 06 00 00 2b 13 03 16 fe 02 0d 09}  //weight: 4, accuracy: Low
        $x_1_2 = {03 16 fe 02 0d 09 2c 0b 00 02 03 04 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_HHR_2147935838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.HHR!MTB"
        threat_id = "2147935838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c}  //weight: 6, accuracy: Low
        $x_5_2 = {02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0a 06 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SKEA_2147936304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SKEA!MTB"
        threat_id = "2147936304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 04 73 02 00 00 0a 13 05 73 03 00 00 0a 13 06 11 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 05 00 00 0a 13 07 11 07 08 16 08 8e 69 6f ?? 00 00 0a 17 0b 11 06 6f ?? 00 00 0a 13 08}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZHE_2147936480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZHE!MTB"
        threat_id = "2147936480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8d 3d 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 02}  //weight: 6, accuracy: Low
        $x_5_2 = {08 1f 28 5d 1b 58 13 0a 02 08 11 07 6f ?? 00 00 0a 13 0b 04 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SXDA_2147936718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SXDA!MTB"
        threat_id = "2147936718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 06}  //weight: 2, accuracy: Low
        $x_1_2 = {08 11 06 58 1f 64 5d 13 07 11 07 1f 1e 32 14 11 07 1f 46 32 07 72 1b 01 00 70 2b 0c 72 25 01 00 70 2b 05 72 2f 01 00 70 13 08 02 08 11 06 6f ?? 00 00 0a 13 09 04 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_EAB_2147936809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.EAB!MTB"
        threat_id = "2147936809"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 07 06 11 07 28 04 00 00 2b 13 08 12 08 28 7a 00 00 0a 23 9a 99 99 99 99 99 e9 3f 5a 69 58 0b 00 11 07 17 58 13 07 11 07 06 6f 7b 00 00 0a fe 04 13 09 11 09 2d c9}  //weight: 5, accuracy: High
        $x_5_2 = {00 07 6f 8f 00 00 0a 0d 09 6f 90 00 00 0a 13 04 09 6f 91 00 00 0a 13 05 11 04 17 58 1b 2f 11 06 11 04 17 58 11 05 28 92 00 00 0a 16 fe 01 2b 01 16 13 06 11 06 2c 12 07 11 04 17 58 11 05 73 8d 00 00 0a 6f 8e 00 00 0a 00 00 08 17 58 0c 08 19 2f 0b 07 6f 93 00 00 0a 16 fe 02 2b 01 16 13 07 11 07 2d 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SUDA_2147937030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SUDA!MTB"
        threat_id = "2147937030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 0f 00 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? ?? ?? 06 16 61 d2 9c 25 17 0f 00 28 ?? 00 00 0a 16 60 d2 9c 25 18 0f 00 28 ?? 01 00 0a 20 ff 00 00 00 5f d2 9c 13 08 17 13 13 2b 83}  //weight: 2, accuracy: Low
        $x_1_2 = {04 19 8d b0 00 00 01 25 16 08 9c 25 17 09 9c 25 18 11 04 9c 6f ?? 01 00 0a 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZZC_2147937732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZZC!MTB"
        threat_id = "2147937732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 09 07 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 1f 32 2f 18 12 04 28 ?? 00 00 0a 1f 32 2f 0d 12 04 28 ?? 00 00 0a 1f 64 fe 02 2b 01 16 13 05 11 05 2c 14 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVF_2147939145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVF!MTB"
        threat_id = "2147939145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 cc 00 00 00 1e 00 00 00 ab 01 00 00 07 01 00 00 2a 01 00 00 ad 01 00 00 2a 00 00 00 01 00 00 00 44 00 00 00 04 00 00 00 26 00 00 00 2b 00 00 00 07 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 0f 00 00 00 08 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "d4e02ce4-42ac-402e-9116-b48ca8c63d33" ascii //weight: 1
        $x_1_3 = "QLBH.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVF_2147939145_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVF!MTB"
        threat_id = "2147939145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 7d a2 1d 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 76 00 00 00 0d 00 00 00 36 00 00 00 43 00 00 00 2b 00 00 00 d3 00 00 00 03 00 00 00 34 00 00 00 01 00 00 00 01 00 00 00 10 00 00 00 08 00 00 00 1a 00 00 00 24 00 00 00 02 00 00 00 05 00 00 00 03 00 00 00 01 00 00 00 07 00 00 00 03}  //weight: 1, accuracy: High
        $x_1_2 = "F1E2D3C4-B5A6-9785-432F-876543210ABC" ascii //weight: 1
        $x_1_3 = "PitchAnalytics.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZKW_2147940375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZKW!MTB"
        threat_id = "2147940375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {08 06 11 04 6f ?? 01 00 0a 13 14 09 07 6f ?? 00 00 0a 59 13 06 11 06 19 fe 04 16 fe 01 13 0c 11 0c 2c 54}  //weight: 6, accuracy: Low
        $x_5_2 = {25 16 12 14 28 ?? 01 00 0a 9c 25 17 12 14 28 ?? 01 00 0a 9c 25 18 12 14 28 ?? 01 00 0a 9c 13 0d 11 09 20 d4 71 77 51 28 ?? 00 00 06 28 ?? 01 00 0a 2c 03 16 2b 01 16 13 0e 11 0e 2c 07 12 0d 28 ?? 00 00 06 07 11 0d 6f ?? 00 00 0a 2b 53 11 06 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PKDZ_2147940439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PKDZ!MTB"
        threat_id = "2147940439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {72 61 00 00 70 28 24 00 00 0a 0a 72 93 00 00 70 28 24 00 00 0a 0b 28 09 00 00 06 0c 12 02 28 18 00 00 0a 75 03 00 00 1b 0d 12 02 28 19 00 00 0a 73 25 00 00 0a 13 04 11 04 06 07 6f 26 00 00 0a 13 05 73 17 00 00 0a 13 06 11 06 11 05 17 73 27 00 00 0a 13 07 11 07 09 16 09 8e 69 6f 28 00 00 0a 11 06 6f 29 00 00 0a 28 1b 00 00 0a 13 08 dd 2d 00 00 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ANSA_2147940455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ANSA!MTB"
        threat_id = "2147940455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 1f 1c 28 ?? 00 00 06 28 ?? 00 00 06 09 1f 20 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 25 26 1f 38 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 25 26 13 04 11 04 07 1f 24 28 ?? 00 00 06 28 ?? 00 00 06 25 26 13 05 09 11 05 09 28 ?? 00 00 06 25 26 1f 28 28 ?? 00 00 06 5b 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 09 11 05 09 28 ?? ?? 00 06 25 26 1f 2c 28 ?? 00 00 06 5b 28 ?? 00 00 06 25 26 28 ?? 00 00 06 09 1f 30 28 ?? 00 00 06 28 ?? 00 00 06 08 09 28 ?? 00 00 06 25 26 1f 34 28 ?? 00 00 06 28 ?? 00 00 06 25 26 13 06 11 06 02 1f 38 28 ?? 00 00 06 02 28 ?? ?? 00 06 25 26 69 28 ?? 00 00 06 11 06 28 ?? ?? 00 06 de 1f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ACUA_2147941478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ACUA!MTB"
        threat_id = "2147941478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 08 16 07 16 1f 10 28 ?? 01 00 06 7e ?? 00 00 04 08 16 07 1f 0f 1f 10 28 ?? 01 00 06 7e ?? 00 00 04 06 07 28 ?? 01 00 06 7e ?? 00 00 04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 19 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BFH_2147941500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BFH!MTB"
        threat_id = "2147941500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 8e 69 1a 2f 07 16 0b dd b8 00 00 00 20 24 67 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0c 20 5d 66 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 1e 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 20 00 00 0a 13 06 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 03 11 05 6f ?? 00 00 0a 6f ?? 00 00 06 17 0b de 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ALUA_2147941709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ALUA!MTB"
        threat_id = "2147941709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 04 28 ?? 00 00 06 0c 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 03 28 ?? 00 00 0a 0d 06 6f ?? 00 00 0a 13 04 11 04 09 16 09 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 de 14}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MYV_2147941866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MYV!MTB"
        threat_id = "2147941866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {04 1f 09 7e 17 01 00 04 1f 6e 7e 17 01 00 04 1f 6e 93 04 5f 20 fd 00 00 00 5f 9d 5d 2c 04 18 0c 2b c0 17 2b fa 03 2b 07 03 20 ed 00 00 00 61 b4 0a 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ADVA_2147942153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ADVA!MTB"
        threat_id = "2147942153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 17 0b 18 0d 19 0d 28 ?? 00 00 0a 13 04 1a 0d 11 04 17 6f ?? 00 00 0a 1b 0d 11 04 18 6f ?? 00 00 0a 1c 0d 11 04 03 04 6f ?? 00 00 0a 13 05 1d 0d 11 05 02 16 02 8e 69 6f ?? 00 00 0a 0a de 6d}  //weight: 5, accuracy: Low
        $x_2_2 = "FjDyD6U" wide //weight: 2
        $x_1_3 = "CREATEDECRYPTOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AKVA_2147942283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AKVA!MTB"
        threat_id = "2147942283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 2d 19 2b 1c 2b 1d 1d 2d 21 26 72 ?? ?? 01 70 2b 1c 2b 21 2b 22 2b 27 2b 28 2b 2d 17 2c ec de 36 02 2b e1 28 ?? 00 00 06 2b dc 0a 2b dd 28 ?? 00 00 0a 2b dd 06 2b dc 28 ?? 00 00 06 2b d7 06 2b d6 28 ?? 00 00 06 2b d1 0b 2b d0}  //weight: 5, accuracy: Low
        $x_2_2 = {08 02 59 07 59 20 ff 00 00 00 25 2c f7 5f 16 2d 15 d2 0c 08 66 16 2d ed d2 0c 06 07 08 9c 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_PXE_2147942525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.PXE!MTB"
        threat_id = "2147942525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 08 16 13 05 38 88 01 00 00 17 39 56 01 00 00 06 72 11 12 00 70 6f ?? 00 00 0a 16 61 13 06 06 72 25 12 00 70 6f ?? 00 00 0a 16 61 13 07 11 06 11 06 60 20 ff ff ff 7f 5f 13 06 11 07 11 07 60 20 ff ff ff 7f 5f 13 07 02 11 06 11 07 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 16 61 d2 13 09 12 08 28 ?? 00 00 0a 16 61 d2 13 0a 12 08 28 ?? 00 00 0a 16 61 d2 13 0b 07 11 09 6f ?? 00 00 0a 08 11 0a 6f ?? 00 00 0a 09 11 0b 6f ?? 00 00 0a 04 03 6f ?? 00 00 0a 59 13 0c 11 0c 19 32 32 07 6f ?? 00 00 0a 13 0d 08 6f ?? 00 00 0a 13 0e 09 6f ?? 00 00 0a 13 0f 03 11 0d 6f ?? 00 00 0a 03 11 0e 6f ?? 00 00 0a 03 11 0f 6f ?? 00 00 0a 2b 79}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ACF_2147942620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ACF!MTB"
        threat_id = "2147942620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5f 13 0c 02 11 08 11 09 6f ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 13 0e 12 0d 28 ?? 00 00 0a 13 0f 12 0d 28 ?? 00 00 0a 13 10 04 03 6f ?? 00 00 0a 59}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SLYW_2147942775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SLYW!MTB"
        threat_id = "2147942775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 04 00 00 06 72 01 00 00 70 72 33 00 00 70 28 05 00 00 06 72 4d 00 00 70 72 99 00 00 70 28 06 00 00 06 20 00 00 00 00 7e ?? 00 00 04 7b [0-10] 0f 00 00 00 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZPT_2147943565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZPT!MTB"
        threat_id = "2147943565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0a 59 13 18 73 ?? 00 00 0a 13 19 11 19 72 94 22 00 70 12 16 28 ?? 01 00 0a 12 16 28 ?? 01 00 0a 58 12 16 28 ?? 01 00 0a 58 6c 23 00 00 00 00 00 00 08 40 5b 23 00 00 00 00 00 e0 6f 40 5b}  //weight: 6, accuracy: Low
        $x_5_2 = {02 12 06 28 ?? 01 00 0a 12 06 28 ?? 01 00 0a 6f ?? 01 00 0a 13 16 12 06 28 ?? 01 00 0a 13 1b 12 1b 28 ?? 00 00 0a 12 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_APWA_2147943818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.APWA!MTB"
        threat_id = "2147943818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 04 16 94 11 04 17 94 6f ?? 00 00 0a 13 0d 11 04 16 94 1f 64 5d 16 fe 01 13 1f 11 1f 2c 2b 00 11 0a 72 ?? ?? 00 70 12 0d 28 ?? 00 00 0a 12 0d 28 ?? 00 00 0a 58 12 0d 28 ?? 00 00 0a 58 18 5d 16 fe 01 6f ?? 00 00 0a 00 00 19 8d ?? 00 00 01 13 0e 11 0e 16 12 0d 28 ?? 00 00 0a 9c 11 0e 17 12 0d 28 ?? 00 00 0a 9c 11 0e 18 12 0d 28 ?? 00 00 0a 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZES_2147944264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZES!MTB"
        threat_id = "2147944264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 13 01 38 ?? 01 00 00 00 11 02 20 00 01 00 00 6f ?? 00 00 0a 38 ?? 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 ?? 00 00 00 11 02 11 01 6f ?? 00 00 0a 38 ?? 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 ?? 00 00 00 00 02 73 ?? 00 00 0a 13 04 38 ?? 00 00 00 00 11 04 11 03 16}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZGS_2147944404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZGS!MTB"
        threat_id = "2147944404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {16 13 10 11 13 17 58 13 13 11 13 1f 0a fe 04 13 12 00 02 11 2c 11 30 6f ?? 01 00 0a 13 31 11 17 12 31 28 ?? 01 00 0a 58 13 17 11 18 12 31 28 ?? 01 00 0a 58 13 18 11 19 12 31 28 ?? 01 00 0a 58 13 19 12 31}  //weight: 6, accuracy: Low
        $x_5_2 = {11 0e 12 31 28 ?? 01 00 0a 61 d2 13 0e 11 0e 12 31 28 ?? 01 00 0a 61 d2 13 0e 11 0e 12 31 28 ?? 01 00 0a 61 d2 13 0e 11 1a 1f 64 5d 16 fe 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ETL_2147944781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ETL!MTB"
        threat_id = "2147944781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 1f 0f 62 11 0a 75 4f 00 00 1b 11 0c 25 17 58 13 0c 93 11 05 61 60 13 07 1f 0b 13 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ATXA_2147944786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ATXA!MTB"
        threat_id = "2147944786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 19 8c ?? 00 00 01 28 ?? 00 00 0a 16 8c ?? 00 00 01 16 28 ?? 00 00 0a 13 06 11 06 2c 61 08 17 8d ?? 00 00 01 25 16 11 04 a2 14 28 ?? 00 00 0a 16 8c ?? 00 00 01 16 28 ?? 00 00 0a 13 07 11 07 2c 0f 07 20 ff 00 00 00 6f ?? 00 00 0a 00 00 2b 2b 00 07 08 17 8d ?? 00 00 01 25 16 11 04 a2 14 28 ?? 00 00 0a 17 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 00 2b 20 00 07 08 17 8d ?? 00 00 01 25 16 11 04 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 04 09 12 04 28 ?? 00 00 0a 13 08 11 08 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ATYA_2147945574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ATYA!MTB"
        threat_id = "2147945574"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 25 26 0a 28 ?? 00 00 06 0b 00 07 03 28 ?? 00 00 06 00 07 04 28 ?? ?? 00 06 00 07 1f 18 28 ?? 00 00 06 28 ?? ?? 00 06 00 07 1f 1c 28 ?? 00 00 06 28 ?? 00 00 06 00 28 ?? 00 00 06 0c 08 07 28 ?? 00 00 06 1f 20 28 ?? 00 00 06 28 ?? 00 00 06 25 26 0d 00 09 06 1f 24 28 ?? 00 00 06 06 8e 69 28 ?? ?? 00 06 00 09 28 ?? 00 00 06 00 08 28 ?? ?? 00 06 25 26 13 04 de 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZZQ_2147948948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZZQ!MTB"
        threat_id = "2147948948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0e 06 11 04 08 58 61 10 06 02 08 11 04 6f ?? 00 00 0a 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 45 03 00 00 00 54 00 00 00 02 00 00 00 11 00 00 00 2b 2b 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 43 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 27 03 12 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVG_2147949117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVG!MTB"
        threat_id = "2147949117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1d b6 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 98 00 00 00 15 00 00 00 7a 00 00 00 f9 00 00 00 af 00 00 00 37 01 00 00 09 00 00 00 9e 00 00 00 40 00 00 00 01 00 00 00 01 00 00 00 04 00 00 00 28 00 00 00 4c 00 00 00 13 00 00 00 01 00 00 00 01 00 00 00 06 00 00 00 01 00 00 00 0a 00 00 00 18}  //weight: 1, accuracy: High
        $x_1_2 = "8c5c1234-5678-9abc-def0-123456789abc" ascii //weight: 1
        $x_1_3 = "SmartNote.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AWCB_2147949436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AWCB!MTB"
        threat_id = "2147949436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 08 16 08 8e 69 28 ?? ?? 00 0a 08 8e 69 17 59 13 11 16 13 12 2b 15 08 11 12 08 11 12 91 06 11 12 07 5d 91 61 9c 11 12 17 58 13 12 11 12 11 11 31 e5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZLP_2147949619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZLP!MTB"
        threat_id = "2147949619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {06 11 0a 11 06 58 07 19 5f 58 61 0a 02 11 06 11 0a 6f ?? 00 00 0a 13 0b 04 03 6f ?? 00 00 0a 59 13 0c 11 0c 13 0d 11 0d 19 fe 02 13 0e 11 0e 2c 03}  //weight: 6, accuracy: Low
        $x_4_2 = {11 12 2c 10 03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 34 11 11 17 fe 01 13 13 11 13 2c 10}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MCF_2147950847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MCF!MTB"
        threat_id = "2147950847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 30 00 6b 00 6f 00 68 00 4d 00 4b 00 42 00 69 00 34 00 00 17 43 00 41 00 4c 00 43 00 55 00 4c 00 41 00 44 00 4f 00 52 00 41 00 00 0f 46 00 61 00 37 00 34 00 50 00 57 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_MCG_2147951586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.MCG!MTB"
        threat_id = "2147951586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 17 58 07 8e 69 5d 0c 11 20 20 [0-16] 61}  //weight: 2, accuracy: Low
        $x_1_2 = "CSVViewer.Forms.MainForm.resource" ascii //weight: 1
        $x_1_3 = {57 9d a2 29 09 0b 00 00 00 fa 25 33 00 16 00 00 01}  //weight: 1, accuracy: High
        $x_1_4 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVH_2147951899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVH!MTB"
        threat_id = "2147951899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 90 00 00 00 1d 00 00 00 b6 00 00 00 ab 00 00 00 77 00 00 00 0f 01 00 00 88 00 00 00 01 00 00 00 14 00 00 00 09 00 00 00 2a 00 00 00 4a 00 00 00 0e 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 09 00 00 00 06 00 00 00 11}  //weight: 1, accuracy: High
        $x_1_2 = "C4F8B2A6-7D3E-4A9B-B5F1-8E2C6A9D4F7B" ascii //weight: 1
        $x_1_3 = "Source_code.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZIN_2147952578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZIN!MTB"
        threat_id = "2147952578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {18 11 18 58 19 5d 13 1b 19 8d ?? 00 00 01 13 1c 11 1c 16 12 15 28 ?? 00 00 0a 9c 11 1c 17 12 15 28 ?? 00 00 0a 9c 11 1c 18 12 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZVN_2147953705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZVN!MTB"
        threat_id = "2147953705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {1f 09 0b 04 03 07 5d 9a 28 ?? 00 00 0a 02 28 ?? 01 00 06 0a 2b 00 06 2a}  //weight: 6, accuracy: Low
        $x_4_2 = {02 03 60 02 66 03 66 60 5f 0a 2b 00 06 2a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_RVI_2147953743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.RVI!MTB"
        threat_id = "2147953743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1d a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5d 00 00 00 0d 00 00 00 46 00 00 00 3a 00 00 00 2d 00 00 00 97 00 00 00 03 00 00 00 21 00 00 00 10 00 00 00 03 00 00 00 07 00 00 00 0a 00 00 00 05 00 00 00 01 00 00 00 05 00 00 00 05 00 00 00 03 00 00 00 05}  //weight: 1, accuracy: High
        $x_1_2 = "a1b2c3d4-e5f6-7890-abcd-ef1234567890" ascii //weight: 1
        $x_1_3 = "HostPinger.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZFM_2147954212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZFM!MTB"
        threat_id = "2147954212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 6d 5a 11 0a 1b 63 61 61 13 0a 16 13 10 38 ?? 00 00 00 02 11 0f 11 10 6f ?? 00 00 0a 13 11 04 03 6f ?? 00 00 0a 59 13 12 11 12 19 31 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BRM_2147955153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BRM!MTB"
        threat_id = "2147955153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0a 06 14 fe 01 0c 08 2c 0b 72 6d 89 00 70 73 71 01 00 0a 7a 00 06 7e 97 01 00 04 2c 07 7e 97 01 00 04 2b 16 7e 8a 01 00 04 fe 06 03 03 00 06 73 d0 02 00 0a 25 80 97 01 00 04}  //weight: 4, accuracy: High
        $x_5_2 = {04 1b 5d 2c 03 03 2b 07 03 20 cb 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZAL_2147955366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZAL!MTB"
        threat_id = "2147955366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {06 0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 16 02 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 06 fe ?? 46 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 2a}  //weight: 6, accuracy: Low
        $x_4_2 = {25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 2b 24 19}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ABT_2147955499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ABT!MTB"
        threat_id = "2147955499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 06 8e 69 17 da 13 04 16 13 05 2b 23 11 05 1e 5d 16 fe 01 13 06 11 06 2c 0f 06 11 05 06 11 05 91 20 d3 00 00 00 61 9c 00 00 11 05 17 d6 13 05 11 05 11 04 31 d7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZRM_2147955952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZRM!MTB"
        threat_id = "2147955952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 09 11 0b 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 20 de 00 00 00 6a 61 b4 6f ?? 00 00 0a 00 11 0b 15 d6 13 0b 11 0b 16 2f d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GBF_2147956314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GBF!MTB"
        threat_id = "2147956314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 07 1f 20 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 06 28 ?? 34 00 06 28 ?? 34 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "DelegateWriteProcessMemory" ascii //weight: 1
        $x_1_3 = "DelegateResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AHJB_2147956328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AHJB!MTB"
        threat_id = "2147956328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 02 7b ?? 00 00 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 13 05 06 11 05 17 73 ?? 00 00 0a 13 06 00 03 11 06 6f ?? 00 00 0a 1d 2c 01 00 11 06 6f ?? 00 00 0a 00 06 16 6a 6f ?? 00 00 0a 16 2d e0}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GTF_2147956369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GTF!MTB"
        threat_id = "2147956369"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 11 0e 20 83 00 00 00 5a 61 13 10 11 04 11 0f 1f 18 62 11 10 20 ?? ?? ?? ?? 5f 60}  //weight: 5, accuracy: Low
        $x_5_2 = {06 11 13 11 16 1e 5a 1f 1f 5f 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 11 16 17 59 13 16 11 14 17 59 13 14 11 16 16 32 05 11 14 16 30 d3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_SPBC_2147957873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.SPBC!MTB"
        threat_id = "2147957873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? ?? ?? 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 14 0c 2b 0c 00 28 ?? 00 00 06 0c de 03 26 de 00 08 2c f1 07 08 16 08 8e 69 6f ?? 00 00 0a 0d 02 09 28 ?? 00 00 06 de 0a 06 2c 06 06 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_GKV_2147958016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.GKV!MTB"
        threat_id = "2147958016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {04 1e 5d 2c 03 03 2b 07 03 20 cf 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
        $x_4_2 = {2c 07 7e 02 01 00 04 2b 16 7e 01 01 00 04 fe 06 3a 02 00 06 73 02 02 00 0a 25 80 02 01 00 04 28 2c 00 00 2b 28 2d 00 00 2b 0b 00 7e 03 01 00 04 2c 07 7e 03 01 00 04 2b 16}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AB_2147958018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AB!MTB"
        threat_id = "2147958018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3a 5a 01 00 00 11 07 02 6f ?? 00 00 0a 3c 4d 01 00 00 11 08 02 6f ?? 00 00 0a 3c 11 01 00 00 06 6f ?? 00 00 0a 03 3c 34 01 00 00 02 11 07 11 08 6f ?? 00 00 0a 13 09 03 06 6f ?? 00 00 0a 59 13 0a 11 0a 11 04 61 16 2f 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_AD_2147958069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.AD!MTB"
        threat_id = "2147958069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 06 11 07 6f ?? 00 00 0a 13 09 03 11 05 6f ?? 00 00 0a 59 13 0a 11 05 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0a 17 59 25 13 0a 16 fe 02 16 fe 01 13 14 11 14 2c 05 38 ?? 00 00 00 11 05 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0a 17 59 25 13 0a 16 fe 02 16 fe 01 13 15 11 15 2c 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZTJ_2147958628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZTJ!MTB"
        threat_id = "2147958628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 09 11 04 6f ?? 00 00 0a 13 05 03 08 6f ?? 00 00 0a 59 13 06 08 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 11 06 17 59 25 13 06 16}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_ZWJ_2147958980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.ZWJ!MTB"
        threat_id = "2147958980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 04 19 5d 16 fe 01 13 05 11 05 2c 10 07 11 04 07 11 04 91 20 a4 00 00 00 61 b4 9c 00 00 11 04 17 d6 13 04 11 04 09 31 d7 07 0a 2b 00 06 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remcos_BAC_2147959376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remcos.BAC!MTB"
        threat_id = "2147959376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 06 11 0a 11 05 11 0a 11 05 8e 69 5d 91 1f 5a 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 06 8e 69 fe 04 13 0b 11 0b 2d d9 16 13 0c 2b 1e 11 07 11 0c 11 05 11 0c 1d 58 11 05 8e 69 5d 91 20 a7 00 00 00 61 d2 9c 11 0c 17 58 13 0c 11 0c 11 07 8e 69 fe 04 13 0d 11 0d 2d d4}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


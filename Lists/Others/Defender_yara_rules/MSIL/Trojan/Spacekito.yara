rule Trojan_MSIL_Spacekito_A_2147685737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spacekito.A"
        threat_id = "2147685737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spacekito"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InstallDllIE" ascii //weight: 1
        $x_1_2 = "InstallFF" ascii //weight: 1
        $x_1_3 = "Installchrome" ascii //weight: 1
        $x_1_4 = "srvPlgProtect" wide //weight: 1
        $x_1_5 = {2e 00 7a 00 69 00 70 00 ?? ?? 5f 00 6f 00 6c 00 64 00}  //weight: 1, accuracy: Low
        $x_1_6 = "mac=" wide //weight: 1
        $x_1_7 = "\\files\\plugin.zip" wide //weight: 1
        $x_1_8 = {4f 00 4b 00 69 00 74 00 53 00 70 00 61 00 63 00 65 00 ?? ?? 70 00 61 00 70 00 61 00 72 00 72 00 75 00 63 00 68 00 61 00 73 00}  //weight: 1, accuracy: Low
        $x_1_9 = ".max_resumed_crashes\", 10);" wide //weight: 1
        $x_1_10 = "PluginProtect" ascii //weight: 1
        $x_1_11 = "where id like 'OKitSpace%';" wide //weight: 1
        $x_1_12 = "\\Settings\\{3543619C-D563-43F7-95EA-4DA7E1CC396A}" wide //weight: 1
        $x_1_13 = {22 00 6e 00 61 00 6d 00 65 00 22 00 3a 00 [0-2] 22 00 4f 00 4b 00 69 00 74 00 53 00 70 00 61 00 63 00 65 00 22 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_14 = {6d 5f 50 6c 75 67 69 6e 55 52 4c 00}  //weight: 1, accuracy: High
        $x_1_15 = {5f 61 70 70 6c 79 5f 66 66 00 5f 61 70 70 6c 79 5f 69 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_MSIL_Spacekito_B_2147685743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spacekito.B"
        threat_id = "2147685743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spacekito"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InstallDllIE" ascii //weight: 1
        $x_1_2 = "InstallFF" ascii //weight: 1
        $x_1_3 = "IsActiveJsonFF" ascii //weight: 1
        $x_1_4 = "srvProtectExtension" wide //weight: 1
        $x_1_5 = "\\files\\crxID" wide //weight: 1
        $x_1_6 = "mac=" wide //weight: 1
        $x_1_7 = "\\files\\plugin.zip" wide //weight: 1
        $x_1_8 = "BaseFlash" wide //weight: 1
        $x_1_9 = ".max_resumed_crashes\", 10);" wide //weight: 1
        $x_1_10 = " where id like '" wide //weight: 1
        $x_1_11 = {5f 61 70 70 6c 79 5f 66 66 00 5f 61 70 70 6c 79 5f 69 65 00}  //weight: 1, accuracy: High
        $x_1_12 = {2f 00 75 00 20 00 22 00 [0-6] 2f 00 73 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_13 = "updateSrv\\" wide //weight: 1
        $x_1_14 = "FF verify :" wide //weight: 1
        $x_1_15 = "paparruchas" wide //weight: 1
        $x_1_16 = "OkitSpace" wide //weight: 1
        $x_1_17 = "&sver=" wide //weight: 1
        $x_1_18 = {6d 5f 55 73 65 72 5f 69 64 00 6d 5f 63 68 61 6e 6e 65 6c 5f 69 64}  //weight: 1, accuracy: High
        $x_1_19 = "\\files\\pluginCRXsm.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_MSIL_Spacekito_C_2147686769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spacekito.C"
        threat_id = "2147686769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spacekito"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "srvProtectExtension" wide //weight: 1
        $x_1_2 = "\\versionPPSrv" wide //weight: 1
        $x_1_3 = "\\updateSrv" wide //weight: 1
        $x_1_4 = "BaseFlash" wide //weight: 1
        $x_1_5 = "OkitSpace" wide //weight: 1
        $x_1_6 = {63 68 61 6e 6e 65 6c 5f 73 75 62 69 64 00 63 68 61 6e 6e 65 6c 5f 70 61 72 61 6d 00 75 73 65 72 5f 6f 73}  //weight: 1, accuracy: High
        $x_1_7 = {6d 5f 61 70 70 6c 79 5f 66 66 00 6d 5f 61 70 70 6c 79 5f 69 65 00 6d 5f 61 70 70 6c 79 5f 63 68}  //weight: 1, accuracy: High
        $x_1_8 = {53 00 45 00 4c 00 45 00 43 00 54 00 [0-2] 20 00 2a 00 20 00 [0-2] 46 00 52 00 4f 00 4d 00 20 00 [0-2] 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00}  //weight: 1, accuracy: Low
        $x_1_9 = {72 00 65 00 73 00 [0-4] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_10 = "ExtensionFF.exe" wide //weight: 1
        $x_1_11 = "\\ExIE\\" wide //weight: 1
        $x_1_12 = "EIE.zip" wide //weight: 1
        $x_1_13 = "EFF.zip" wide //weight: 1
        $x_1_14 = "ECH.zip" wide //weight: 1
        $x_1_15 = "mac=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spacekito_D_2147686770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spacekito.D"
        threat_id = "2147686770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spacekito"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 5f 66 69 72 65 66 6f 78 5f 65 78 65 00 6d 5f 70 72 6f 6a 65 63 74 00 6d 5f 70 6c 75 67 69 6e 55 52 4c}  //weight: 1, accuracy: High
        $x_1_2 = {56 65 72 69 66 79 46 46 00 49 6e 73 74 61 6c 6c 46 46}  //weight: 1, accuracy: High
        $x_1_3 = "OkitSpace" wide //weight: 1
        $x_1_4 = "appDisabled FROM addon WHERE id LIKE '##%';" wide //weight: 1
        $x_1_5 = "\\ff.sql\" | \"" wide //weight: 1
        $x_1_6 = "\\chrome\\content\\main.js" wide //weight: 1
        $x_1_7 = "channel_subid" wide //weight: 1
        $x_1_8 = "user_antivirus" wide //weight: 1
        $x_1_9 = {52 00 65 00 57 00 69 00 6e 00 55 00 70 00 [0-128] 40 00 52 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_10 = {50 00 6c 00 75 00 67 00 69 00 6e 00 ?? ?? 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 ?? ?? 4f 00 53 00 ?? ?? 38 00}  //weight: 1, accuracy: Low
        $x_1_11 = "ExtensionFF.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_MSIL_Spacekito_E_2147687438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spacekito.E"
        threat_id = "2147687438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spacekito"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 65 72 69 66 79 49 45 00 49 6e 73 74 61 6c 6c 44 6c 6c 49 45 00 66 69 6c 65 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {6d 5f 50 6c 75 67 69 6e 55 52 4c 00 6d 5f 63 66 67 5f 63 6f 6e 74 65 6e 74 00 64 69 72 4f 75 74 70 75 74}  //weight: 1, accuracy: High
        $x_1_3 = "\\Ext\\Settings\\{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE53}" wide //weight: 1
        $x_1_4 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-128] 70 00 6c 00 75 00 67 00 69 00 6e 00 49 00 45 00 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {75 00 70 00 64 00 61 00 74 00 65 00 ?? ?? 2e 00 7a 00 69 00 70 00 [0-128] 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {49 00 67 00 6e 00 6f 00 72 00 65 00 46 00 72 00 61 00 6d 00 65 00 41 00 70 00 70 00 72 00 6f 00 76 00 61 00 6c 00 43 00 68 00 65 00 63 00 6b 00 ?? ?? 31 00}  //weight: 1, accuracy: Low
        $x_1_7 = "channel_subid" wide //weight: 1
        $x_1_8 = "user_antivirus" wide //weight: 1
        $x_1_9 = {70 00 6c 00 75 00 67 00 69 00 6e 00 49 00 45 00 [0-144] 2e 00 64 00 6c 00 6c 00 ?? ?? 63 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 1, accuracy: Low
        $x_1_10 = "ExtensionIE.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spacekito_F_2147687469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spacekito.F"
        threat_id = "2147687469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spacekito"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 65 72 69 66 79 43 48 00 72 65 73 74 6f 72 65 43 52 58 00 73 65 74 52 65 67 69 73 74 72 79 43 52 58}  //weight: 1, accuracy: High
        $x_1_2 = {6d 5f 63 68 72 6f 6d 65 5f 69 64 00 6d 5f 50 6c 75 67 69 6e 55 52 4c 00 6d 5f 70 61 72 61 6d 65 74 65 72 73}  //weight: 1, accuracy: High
        $x_1_3 = {75 00 70 00 64 00 61 00 74 00 65 00 ?? ?? 2e 00 7a 00 69 00 70 00 [0-128] 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {70 00 6c 00 75 00 67 00 69 00 6e 00 43 00 48 00 [0-144] 2e 00 63 00 72 00 78 00 [0-128] 70 00 61 00 74 00 68 00 [0-128] 6b 00 6e 00 6f 00 77 00 6e 00 5f 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00 22 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {75 00 73 00 65 00 72 00 5f 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 5f 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 ?? ?? 75 00 73 00 65 00 72 00 5f 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {74 00 65 00 6d 00 70 00 43 00 52 00 58 00 5c 00 [0-128] 2e 00 70 00 65 00 6d 00 [0-128] 70 00 6c 00 75 00 67 00 69 00 6e 00 43 00 48 00 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = "\"install_warning_on_enable\": false," wide //weight: 1
        $x_1_8 = "\"restore_on_startup\": 1," wide //weight: 1
        $x_1_9 = "\" --pack-extension-key=\"" wide //weight: 1
        $x_1_10 = "ExtensionCH.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


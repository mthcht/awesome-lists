rule Trojan_MSIL_Keylogger_SC_2147745490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.SC!MSR"
        threat_id = "2147745490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KurdishCoderProducts" ascii //weight: 1
        $x_1_2 = "SELECT * FROM Customers" wide //weight: 1
        $x_1_3 = "DataGridViewPrinterApplication.exe" wide //weight: 1
        $x_1_4 = "OleDbData" ascii //weight: 1
        $x_1_5 = "EditorBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_AA_2147748022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.AA!MTB"
        threat_id = "2147748022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyHack" ascii //weight: 1
        $x_1_2 = "KeyloggerExecutor" ascii //weight: 1
        $x_1_3 = "costura.keylogger.dll.compressed" wide //weight: 1
        $x_1_4 = "costura.costura.dll.compressed" wide //weight: 1
        $x_1_5 = "KeyloggerConfig" ascii //weight: 1
        $x_1_6 = "StartLogging" ascii //weight: 1
        $x_1_7 = "SteamService.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_VN_2147759331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.VN!MTB"
        threat_id = "2147759331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 0c 08 6f ?? ?? ?? 0a 26 16 0d 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_KS_2147761078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.KS"
        threat_id = "2147761078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "5A58D9E17AAB058BAB55371BCAD8BF667EA82E31465B3F69B368DFBC930B724D" ascii //weight: 2
        $x_2_2 = "F3B18921554AFB9072B5B0AEE618FEE8904FBAAF237AFE2CDD1A38E3038415E7" ascii //weight: 2
        $x_1_3 = "EnableKeylogger" ascii //weight: 1
        $x_1_4 = "EnableBotKiller" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Keylogger_DA_2147779338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.DA!MTB"
        threat_id = "2147779338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$074b6d25-19b1-4049-bedb-33fd2867b7bd" ascii //weight: 20
        $x_20_2 = "$88771a07-7de2-4cb8-b1f9-7338f3347bbb" ascii //weight: 20
        $x_20_3 = "$94db0597-e054-42c5-9bc7-0eaed7c9149c" ascii //weight: 20
        $x_5_4 = "DebuggableAttribute" ascii //weight: 5
        $x_5_5 = "DebuggingModes" ascii //weight: 5
        $x_1_6 = "dTzkehxHXTvZxMOGmbAPMiXdtTsr.resources" ascii //weight: 1
        $x_1_7 = "Sarawar.Properties.Resources" ascii //weight: 1
        $x_1_8 = "C.PrivateStubWinForm.Properties.Resources" ascii //weight: 1
        $x_1_9 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
        $x_1_12 = "CreateDecryptor" ascii //weight: 1
        $x_1_13 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Keylogger_DC_2147779728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.DC!MTB"
        threat_id = "2147779728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 00 40 01 00 8d 46 00 00 01 0a 2b 09 03 06 16 07 6f 60 00 00 0a 02 06 16 06 8e 69 6f 61 00 00 0a 25 0b 2d e8}  //weight: 1, accuracy: High
        $x_1_2 = {20 e7 03 00 00 28 02 00 00 0a 00 00 08 17 58 0c 08 1f 0f fe 04 0d 09 2d e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_AR_2147781318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.AR!MTB"
        threat_id = "2147781318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 0c 1f 0a 0d 72 ?? ?? ?? 70 13 04 16 13 05 2b 30 00 06 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 06 11 04 07 11 06 28 ?? ?? ?? 2b 13 07 12 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 00 11 05 17 58 13 05 11 05 09 fe 04 13 08 11 08 2d c5}  //weight: 10, accuracy: Low
        $x_5_2 = "!@#$%^&()[]{}" ascii //weight: 5
        $x_5_3 = "KEYLOGGER" ascii //weight: 5
        $x_4_4 = "UploadFile" ascii //weight: 4
        $x_4_5 = "/UPLOADENC.php/" ascii //weight: 4
        $x_4_6 = "POST" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_4_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Keylogger_ADG_2147781329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.ADG!MTB"
        threat_id = "2147781329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 0a 28 14 00 00 0a 00 16 13 06 2b 54 00 11 06 28 ?? ?? ?? 06 13 07 11 07 17 2e 0b 11 07 20 01 80 ff ff fe}  //weight: 10, accuracy: Low
        $x_3_2 = "Saved keys from" ascii //weight: 3
        $x_3_3 = "Keystrokes saved from user" ascii //weight: 3
        $x_3_4 = "SmtpClient" ascii //weight: 3
        $x_3_5 = "GetAsyncKeyState" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_ADG_2147781329_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.ADG!MTB"
        threat_id = "2147781329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "antiSandboxie" ascii //weight: 4
        $x_4_2 = "AddToAutorun" ascii //weight: 4
        $x_4_3 = "AntiVirtualBox" ascii //weight: 4
        $x_4_4 = "AntiVmWare" ascii //weight: 4
        $x_4_5 = "AntiWireShark" ascii //weight: 4
        $x_3_6 = "GetAsyncKeyState" ascii //weight: 3
        $x_3_7 = "getDevices" ascii //weight: 3
        $x_3_8 = "CAPSLOCKON" ascii //weight: 3
        $x_3_9 = "MouseEnter" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Keylogger_FGR_2147781336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.FGR!MTB"
        threat_id = "2147781336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "frmspklgr_setup.resources" ascii //weight: 3
        $x_3_2 = "ESPIER KEYLOGGER" ascii //weight: 3
        $x_3_3 = "updatekey" ascii //weight: 3
        $x_3_4 = "spklgr.lnk" ascii //weight: 3
        $x_3_5 = "Resources.reg.des.reg" ascii //weight: 3
        $x_3_6 = "spklgr.Licencia.txt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_FGR_2147781336_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.FGR!MTB"
        threat_id = "2147781336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 16 7d 10 00 00 04 02 06 6a 28 2c 00 00 06 7d 10 00 00 04 02 7b 10 00 00 04 20 01 80 ff ff 33 26 02}  //weight: 10, accuracy: High
        $x_5_2 = "GetAsyncKeyState" ascii //weight: 5
        $x_5_3 = "get_FileSystem" ascii //weight: 5
        $x_4_4 = "@vorfin@" ascii //weight: 4
        $x_4_5 = "SmtpClient" ascii //weight: 4
        $x_4_6 = "MailMessage" ascii //weight: 4
        $x_4_7 = "set_Credentials" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_ADQ_2147781338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.ADQ!MTB"
        threat_id = "2147781338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LowLevelKeyboardProc" ascii //weight: 5
        $x_5_2 = "GetKeyState" ascii //weight: 5
        $x_5_3 = "KeyboardLayout" ascii //weight: 5
        $x_4_4 = "[SPACE]" ascii //weight: 4
        $x_4_5 = "[ENTER]" ascii //weight: 4
        $x_4_6 = "[ESC]" ascii //weight: 4
        $x_4_7 = "[CTRL]" ascii //weight: 4
        $x_4_8 = "GetKeyboardState" ascii //weight: 4
        $x_3_9 = "SWRat" ascii //weight: 3
        $x_3_10 = "WINDOWS_FIREWALL_SERVICE" ascii //weight: 3
        $x_3_11 = "Hacked" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_ADS_2147781624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.ADS!MTB"
        threat_id = "2147781624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LowLevelKeyboardProc" ascii //weight: 3
        $x_3_2 = "GetKeyState" ascii //weight: 3
        $x_3_3 = "KeyboardLayout" ascii //weight: 3
        $x_3_4 = "[SPACE]" ascii //weight: 3
        $x_3_5 = "[ENTER]" ascii //weight: 3
        $x_3_6 = "[ESC]" ascii //weight: 3
        $x_3_7 = "[CTRL]" ascii //weight: 3
        $x_3_8 = "Keylogger" ascii //weight: 3
        $x_3_9 = "MapVirtualKey" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_DD_2147782117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.DD!MTB"
        threat_id = "2147782117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 39 11 31 6f ?? ?? ?? 0a 13 3a 72 ?? ?? ?? 70 13 3b 17 13 3c 2b 16 72 ?? ?? ?? 70 13 52 72 ?? ?? ?? 70 13 53 72 ?? ?? ?? 70 13 54 00 11 3c 11 3a fe 02 16 fe 01 13 55 11 55 2d db}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_DE_2147787433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.DE!MTB"
        threat_id = "2147787433"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetOutlookPasswords" ascii //weight: 1
        $x_1_2 = "GetKeyloggerData" ascii //weight: 1
        $x_1_3 = "DisableRegistryTools" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
        $x_1_5 = "UploadData" ascii //weight: 1
        $x_1_6 = "thekeydata.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_EY_2147788361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.EY!MTB"
        threat_id = "2147788361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 72 cf 09 00 70 12 00 fe 16 28 00 00 01 6f 3c 00 00 0a 72 d5 09 00 70 28 3d 00 00 0a 28 1f 00 00 06 00 38 8b 00 00 00 02 72 db 09 00 70 28 1f 00 00 06 00 2b 7d 02 72 df 09 00 70 28 1f 00 00 06 00 2b 6f 02 72 e3 09 00 70 28 1f 00 00 06 00 2b 61 17 13 12 dd b2 00 00 00 28 16 00 00 06 13 0a 11 0a 12 0b 28 19 00 00 06 13 0c 20 00 01 00 00 8d 5a 00 00 01 13 0d 11 0d 28 18 00 00 06 26 11 0c 28 1a 00 00 06 13 0e 73 78 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "keylog.Properties.Resources" wide //weight: 1
        $x_1_3 = "KeyL.html" wide //weight: 1
        $x_1_4 = "khaled0596@gmail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_AM_2147818868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.AM!MTB"
        threat_id = "2147818868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger started." wide //weight: 1
        $x_1_2 = "sendkeylog.php" wide //weight: 1
        $x_1_3 = "unable to delete keystrokes.txt" wide //weight: 1
        $x_1_4 = "Desktop Capture started." wide //weight: 1
        $x_1_5 = "Goodbye" wide //weight: 1
        $x_1_6 = "Keylogger stopped." wide //weight: 1
        $x_1_7 = "StartKeylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_PA3_2147819059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.PA3!MTB"
        threat_id = "2147819059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://discord.gg/udRhm3hYHM" ascii //weight: 2
        $x_1_2 = "keylog" ascii //weight: 1
        $x_1_3 = "SELECT * FROM botnet.help;" ascii //weight: 1
        $x_1_4 = "PASSWORD=" ascii //weight: 1
        $x_1_5 = "SERVER=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_ABS_2147829263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.ABS!MTB"
        threat_id = "2147829263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {57 3f a2 1f 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 04 01 00 00 49 00 00 00 ae 00 00 00 b1 01 00 00 a2 01 00 00}  //weight: 6, accuracy: High
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "get_WorkingDirectory" ascii //weight: 1
        $x_1_4 = "GetFolderPath" ascii //weight: 1
        $x_1_5 = "GetFileDropList" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "get_KeyboardDevice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_BE_2147829930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.BE!MTB"
        threat_id = "2147829930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Intern\\keylog\\keylog\\obj\\Debug\\keylog.pdb" ascii //weight: 1
        $x_1_2 = "$f06dc3ca-72cb-42ba-a96f-7e04909a4d63" ascii //weight: 1
        $x_1_3 = "c:\\windows\\key.txt" wide //weight: 1
        $x_1_4 = "c:\\windows\\keylog.exe" wide //weight: 1
        $x_1_5 = "SOFTWARE\\keylog" wide //weight: 1
        $x_1_6 = "Form1_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_NKK_2147838500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.NKK!MTB"
        threat_id = "2147838500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 fb 01 00 70 28 ?? 00 00 0a 74 ?? 00 00 01 0b 07 6f ?? 00 00 0a 74 ?? 00 00 01 0c 08 6f ?? 00 00 0a 0d 09 73 ?? 00 00 0a 13 04 00 00 11 04 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "CatHack.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_NKL_2147849603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.NKL!MTB"
        threat_id = "2147849603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 15 00 00 0a 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 04 00 11 04 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 00 11 05 07 16 07 8e 69 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Fx4beta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_NKL_2147849603_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.NKL!MTB"
        threat_id = "2147849603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f ca 00 00 06 2c 06 73 ?? 00 00 0a 7a 03 11 04 1f 50 58 28 ?? 00 00 0a 13 09 03 11 04 1f 54 58 28 ?? 00 00 0a 13 0a 16}  //weight: 5, accuracy: Low
        $x_1_2 = "SecureHorizons.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_NKL_2147849603_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.NKL!MTB"
        threat_id = "2147849603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f e2 00 00 0a 0b 07 16 73 ?? ?? 00 0a 13 0b 11 0b 73 ?? ?? 00 0a 13 04 7e ?? ?? 00 04 11 04 7e ?? ?? 00 04 11 04 28 ?? ?? 00 06 28 ?? ?? 00 06 13 05}  //weight: 5, accuracy: Low
        $x_1_2 = "Anarchy.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_NKL_2147849603_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.NKL!MTB"
        threat_id = "2147849603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 24 00 00 0a 02 6f ?? ?? ?? 0a 0a 06 6f ?? ?? ?? 0a 0b 06 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 17 8d ?? ?? ?? 01 0d 07 6f ?? ?? ?? 0a 8e 69 2d 02 14 0d 07 08 09 6f ?? ?? ?? 0a 26 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {73 1f 00 00 0a 0a 28 ?? ?? ?? 0a 02 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 2a}  //weight: 5, accuracy: Low
        $x_1_3 = "n0lC45eoWgjOlr_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_CXFW_2147850273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.CXFW!MTB"
        threat_id = "2147850273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Keylogger\\obj\\Debug\\" ascii //weight: 1
        $x_1_2 = "sys_data_capture_" wide //weight: 1
        $x_1_3 = "echo Gathering Debugging Informatin" wide //weight: 1
        $x_1_4 = "echo Computer Name:" wide //weight: 1
        $x_1_5 = "ipconfig /all >>" wide //weight: 1
        $x_1_6 = "del %tmp%\\sys_data_capture*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_PSSV_2147851383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.PSSV!MTB"
        threat_id = "2147851383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 21 07 16 12 0e 7b 21 00 00 04 28 ?? 00 00 0a 06 72 2f 0f 00 70 28 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 0a 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_PSWO_2147889555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.PSWO!MTB"
        threat_id = "2147889555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2c 3a 00 04 28 ?? 00 00 0a 0b 07 0d 12 03 fe 16 06 00 00 01 6f ?? 00 00 0a 0c 08 28 ?? 00 00 0a 16 fe 01 13 04 11 04 2c 12 00 7e 05 00 00 04 08 28 ?? 00 00 0a 80 05 00 00 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_AH_2147896075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.AH!MTB"
        threat_id = "2147896075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[Page Down]" ascii //weight: 3
        $x_3_2 = "[Home]" ascii //weight: 3
        $x_3_3 = "[Insert]" ascii //weight: 3
        $x_3_4 = "[End]" ascii //weight: 3
        $x_3_5 = "[Esc]" ascii //weight: 3
        $x_3_6 = "ClipboardProxy" ascii //weight: 3
        $x_3_7 = "Your Polymorphic Keylogger has been activated on" ascii //weight: 3
        $x_3_8 = "\\Windows Firewall\\config\\" ascii //weight: 3
        $x_3_9 = "DisableSR" ascii //weight: 3
        $x_3_10 = "get_PrimaryScreen" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_ABEK_2147896491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.ABEK!MTB"
        threat_id = "2147896491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 fe 01 13 07 11 07 2d 31 00 28 ?? ?? ?? 0a 13 04 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 05 11 04 11 05 17 28 ?? ?? ?? 0a 00 00 02 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 13 06 11 06 16 1f 7c 9d 11 06 6f ?? ?? ?? 0a 16 9a 73 ?? ?? ?? 06 7d ?? ?? ?? 04 00 de 05}  //weight: 2, accuracy: Low
        $x_1_2 = "msoklogs" wide //weight: 1
        $x_1_3 = "msoklogs.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_ABAS_2147896516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.ABAS!MTB"
        threat_id = "2147896516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 28 01 00 00 06 0d 09 20 01 80 00 00 40 aa 02 00 00 72 56 01 00 70 13 04 7e 01 00 00 04 17 58 80 01 00 00 04 08 28 15 00 00 0a 28 09 00 00 06 13 04 72 58 01 00 70 17}  //weight: 1, accuracy: High
        $x_1_2 = "keylogger" ascii //weight: 1
        $x_1_3 = "uac_true" wide //weight: 1
        $x_1_4 = "persistence_true" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_NL_2147898266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.NL!MTB"
        threat_id = "2147898266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7e 57 00 00 04 06 7e 56 00 00 04 02 07 6f 28 00 00 0a 7e 27 00 00 04 07 7e 27 00 00 04 8e 69 5d 91 61 28 ca 00 00 06 28 cf 00 00 06 26 07 17 58 0b 07 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_AMBF_2147898317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.AMBF!MTB"
        threat_id = "2147898317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 7a 7d 03 4b 9b 5d d1 f5 8e 38 93 54 10 01 4b d3 95 35 49 4b 1f 01 bd f3 cb f8 d9 24 74 6f d8 92 13 c4 27 7b bb 9c ad 03 1a 51 a0 eb b0}  //weight: 1, accuracy: High
        $x_1_2 = {c7 6c 76 b4 f1 16 aa a5 a7 ea 3d 49 aa c1 87 44 77 c0 90 57 7c e7 2d d1 91 4a 80 bc df 69 fe 84 ff 5c 4b e0 49 82 b5 fe ea cd 22 e2 0f a1 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_PSA_2147899283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.PSA!MTB"
        threat_id = "2147899283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {80 9b 00 00 04 73 4e 01 00 0a 80 9a 00 00 04 7e 16 ?? ?? ?? 7e 98 00 00 04 28 5f ?? ?? ?? 80 9c 00 00 04 7e ed 01 00 04 28 08 ?? ?? ?? 19 3a 8d 00 00 00 26 7e 18 ?? ?? ?? 06 72 0f 00 00 70 28 62 ?? ?? ?? 16 2c 7f 26 1e 2c 48 7e 1b ?? ?? ?? 7e 1a ?? ?? ?? 07 28 65 ?? ?? ?? 28 68 ?? ?? ?? 1b 2d 3d 26 08 8d 99 00 00 01 1d 2d 36 26}  //weight: 5, accuracy: Low
        $x_1_2 = "ICryptoTransform" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "DeriveBytes" ascii //weight: 1
        $x_1_5 = "SymmetricAlgorithm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_PSBJ_2147899325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.PSBJ!MTB"
        threat_id = "2147899325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 7e 08 00 00 04 28 19 00 00 0a 16 fe 01 0a 06 2c 0d 00 7e 08 00 00 04 28 1a 00 00 0a 26 00 7e 09 00 00 04 28 1b 00 00 0a 16 fe 01 0b 07 2c 1c 00 7e 09 00 00 04 28 1c 00 00 0a 0c}  //weight: 5, accuracy: High
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "WriteLine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_DB_2147899385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.DB!MTB"
        threat_id = "2147899385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 7e 59 00 00 04 07 06 6f 92 00 00 0a 28 93 00 00 0a 0d 28 91 00 00 0a 09 16 09 8e 69 6f 92 00 00 0a 28 94 00 00 0a 13 04 7e 5c 00 00 04 2c 08 02 11 04 28 bc 00 00 06 11 04 13 05 de 06}  //weight: 1, accuracy: High
        $x_1_2 = {2d da 16 2d d7 2a 0a 2b ce 03 2b d5 06 2b d4 07 2b d4 6f ?? ?? ?? 0a 2b d4 02 2b d6 06 2b d5 06 2b d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_PTGC_2147900859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.PTGC!MTB"
        threat_id = "2147900859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 32 00 00 04 28 ?? 00 00 06 28 ?? 00 00 0a 2c 0a 11 04 09 6f d2 00 00 0a 2b 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_LL_2147901054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.LL!MTB"
        threat_id = "2147901054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 19 01 00 04 0e 06 17 59 e0 95 58 0e 05 28 ac 02 00 06 58 54}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_SAA_2147927537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.SAA!MTB"
        threat_id = "2147927537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 01 00 00 04 17 73 17 00 00 0a 13 05 02 7b 01 00 00 04 18 28 10 00 00 0a 00 11 05 02 08 28 04 00 00 06 6f 18 00 00 0a 00 11 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_AYA_2147930960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.AYA!MTB"
        threat_id = "2147930960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 58 01 00 70 18 28 17 00 00 0a 11 05 11 04 6f 18 00 00 0a de 0c 11 05 2c 07 11 05 6f 19 00 00 0a dc 1b 28 1a 00 00 0a 72 68 01 00 70 28 1b 00 00 0a 17 73 16 00 00 0a 13 06 1b 28 1a 00 00 0a 72 68 01 00 70 28 1b 00 00 0a 18 28 17 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "keylogger.exe" ascii //weight: 1
        $x_1_3 = "persistence_true" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_AYA_2147930960_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.AYA!MTB"
        threat_id = "2147930960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CocCocCrashHandler.pdb" ascii //weight: 2
        $x_2_2 = "Telegram.Bot.Types" ascii //weight: 2
        $x_1_3 = "KillSameProcessesOnBaseDirectory" ascii //weight: 1
        $x_1_4 = "CaptureActiveWindowToBase64" ascii //weight: 1
        $x_1_5 = "SystemLogger.Hooking" ascii //weight: 1
        $x_1_6 = "GetDiskSerialNumber" ascii //weight: 1
        $x_1_7 = "KeyboardHook_OnKeyDown" ascii //weight: 1
        $x_1_8 = "SELECT UUID FROM Win32_ComputerSystemProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_SEW_2147931943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.SEW!MTB"
        threat_id = "2147931943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Remington.Resources" wide //weight: 1
        $x_1_2 = "Keylogger_Recovered" wide //weight: 1
        $x_1_3 = "Cookies_Recovered" wide //weight: 1
        $x_1_4 = "CreditCard_Recovered" wide //weight: 1
        $x_1_5 = "\\GhostBrowser\\User Data\\Default\\Network\\Cookies" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_AYB_2147935293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.AYB!MTB"
        threat_id = "2147935293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SSH - Key Logger - LOG" wide //weight: 2
        $x_1_2 = "SSH_Keylogger_Stub.Form1.resources" ascii //weight: 1
        $x_1_3 = "$25f03944-9294-4209-8cdc-041755befb97" ascii //weight: 1
        $x_1_4 = "addtoStartup" ascii //weight: 1
        $x_1_5 = "keyboardHookProc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_SWR_2147939427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.SWR!MTB"
        threat_id = "2147939427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 72 ff 02 00 70 08 72 07 03 00 70 28 5f 00 00 0a 11 05 6f 60 00 00 0a 28 7c 00 00 0a 28 7d 00 00 0a 02 7b 0c 00 00 04 72 15 03 00 70 28 73 00 00 0a 73 6a 00 00 0a 6f 25 00 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_PGK_2147940783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.PGK!MTB"
        threat_id = "2147940783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 17 6f ?? 00 00 0a 0d 09 14 fe 01 13 04 11 04 2c 0e 00 7e ?? 00 00 0a 06 6f ?? 00 00 0a 0d 00 09 07 08 6f}  //weight: 2, accuracy: Low
        $x_3_2 = {6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Keylogger_CSI_2147953334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Keylogger.CSI!MTB"
        threat_id = "2147953334"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 7d 3b 00 00 04 72 3f 0f 00 70 73 c7 00 00 06 80 59 00 00 04 7e b2 00 00 04 25 3a 17 00 00 00 26 7e 7d 00 00 04 fe 06 bc 00 00 06 73 1d 00 00 0a 25 80 b2 00 00 04 73 1e 00 00 0a 28 1f 00 00 0a 00 02 fe 06 73 00 00 06 73 1d 00 00 0a 73 1e 00 00 0a 28 1f 00 00 0a 00 02 7b 44 00 00 04 13 04 11 04 39 20 00 00 00 00 02 7b 46 00 00 04 02 7b 45 00 00 04 02 7b 47 00 00 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


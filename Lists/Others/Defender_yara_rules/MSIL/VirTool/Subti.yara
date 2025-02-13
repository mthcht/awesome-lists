rule VirTool_MSIL_Subti_A_2147696038_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.A"
        threat_id = "2147696038"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reverse" ascii //weight: 1
        $x_1_2 = "RemoveZID" ascii //weight: 1
        $x_1_3 = "VMFound" ascii //weight: 1
        $x_1_4 = "SandboxFound" ascii //weight: 1
        $x_1_5 = "Decrypt" ascii //weight: 1
        $x_1_6 = "CompileAndRun" ascii //weight: 1
        $x_1_7 = "AddToStartup" ascii //weight: 1
        $x_1_8 = "RunPE" ascii //weight: 1
        $x_1_9 = "BackupRun" ascii //weight: 1
        $x_1_10 = "RunNet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_MSIL_Subti_A_2147696038_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.A"
        threat_id = "2147696038"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_execution" ascii //weight: 1
        $x_1_2 = "_isDotNet" ascii //weight: 1
        $x_1_3 = "_melt" ascii //weight: 1
        $x_1_4 = "_hide" ascii //weight: 1
        $x_1_5 = "_fakeMessage" ascii //weight: 1
        $x_1_6 = "_processPersistence" ascii //weight: 1
        $x_1_7 = "_antiVm" ascii //weight: 1
        $x_1_8 = "_antiSandboxie" ascii //weight: 1
        $x_1_9 = "_startUpPersistence" ascii //weight: 1
        $x_1_10 = "_binderRunFirst" ascii //weight: 1
        $x_1_11 = "_downloader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_MSIL_Subti_B_2147696039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.B"
        threat_id = "2147696039"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "52657665727365" ascii //weight: 1
        $x_1_2 = "52656D6F76655A4944" ascii //weight: 1
        $x_1_3 = "564D466F756E64" ascii //weight: 1
        $x_1_4 = "53616E64626F78466F756E64" ascii //weight: 1
        $x_1_5 = "44656372797074" ascii //weight: 1
        $x_1_6 = "436F6D70696C65416E6452756E" ascii //weight: 1
        $x_1_7 = "416464546F53746172747570" ascii //weight: 1
        $x_1_8 = "52756E5045" ascii //weight: 1
        $x_1_9 = "4261636B757052756E" ascii //weight: 1
        $x_1_10 = "52756E4E6574" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_MSIL_Subti_B_2147696039_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.B"
        threat_id = "2147696039"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5F657865637574696F6E" ascii //weight: 1
        $x_1_2 = "5F6973446F744E6574" ascii //weight: 1
        $x_1_3 = "5F6D656C74" ascii //weight: 1
        $x_1_4 = "5F68696465" ascii //weight: 1
        $x_1_5 = "5F66616B654D657373616765" ascii //weight: 1
        $x_1_6 = "5F70726F6365737350657273697374656E6365" ascii //weight: 1
        $x_1_7 = "5F616E7469566D" ascii //weight: 1
        $x_1_8 = "5F616E746953616E64626F786965" ascii //weight: 1
        $x_1_9 = "5F7374617274557050657273697374656E6365" ascii //weight: 1
        $x_1_10 = "5F62696E64657252756E4669727374" ascii //weight: 1
        $x_1_11 = "5F646F776E6C6F61646572" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_MSIL_Subti_C_2147696131_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.C"
        threat_id = "2147696131"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":Zone.Identifier" wide //weight: 1
        $x_1_2 = "Fuck AVs" wide //weight: 1
        $x_1_3 = "InjectionPersistence" ascii //weight: 1
        $x_1_4 = "RemoveZoneIdentifier" ascii //weight: 1
        $x_1_5 = "TryInject" ascii //weight: 1
        $x_1_6 = "AddToStartup" ascii //weight: 1
        $x_1_7 = "RunPE" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "echo DONT CLOSE THIS WINDOW!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Subti_D_2147696132_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.D"
        threat_id = "2147696132"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3A005A006F006E0065002E004900640065006E00740069006600690065007200" ascii //weight: 1
        $x_1_2 = "4600750063006B002000410056007300" ascii //weight: 1
        $x_1_3 = "496E6A656374696F6E50657273697374656E6365" ascii //weight: 1
        $x_1_4 = "52656D6F76655A6F6E65496465" ascii //weight: 1
        $x_1_5 = "547279496E6A656374" ascii //weight: 1
        $x_1_6 = "416464546F53746172747570" ascii //weight: 1
        $x_1_7 = "52756E5045" ascii //weight: 1
        $x_1_8 = "44656372797074" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Subti_E_2147696731_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.E"
        threat_id = "2147696731"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Core.Keylogger" ascii //weight: 1
        $x_1_2 = "Core.RemoteShell" ascii //weight: 1
        $x_1_3 = "KeyboardHookStruct" ascii //weight: 1
        $x_1_4 = "SendToTargetServer" ascii //weight: 1
        $x_1_5 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_6 = "echo DONT CLOSE THIS WINDOW!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_F_2147696784_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.F"
        threat_id = "2147696784"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#KILLAMUVZ#" wide //weight: 1
        $x_1_2 = "#KILLA#" wide //weight: 1
        $x_1_3 = {45 6c 65 76 61 74 65 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 65 66 42 72 6f 77 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 75 6e 4e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_G_2147706180_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.G"
        threat_id = "2147706180"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c reg add \"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /f /v shell /t REG_SZ /d \"" wide //weight: 1
        $x_1_2 = "/c reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /f /v \"" wide //weight: 1
        $x_1_3 = ".lnk\"" wide //weight: 1
        $x_1_4 = {70 72 6f 74 65 63 74 50 72 6f 63 00}  //weight: 1, accuracy: High
        $x_1_5 = {69 73 41 64 64 65 64 54 6f 52 65 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {67 65 74 44 65 66 61 75 6c 74 42 72 6f 77 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {5f 43 6f 72 45 78 65 4d 61 69 6e 00 6d 73 63 6f 72 65 65 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_H_2147707576_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.H"
        threat_id = "2147707576"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 6e 74 69 45 6d 75 6c 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 65 00 78 00 65 00 ?? ?? 70 00 69 00 6e 00 67 00 20 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_I_2147707581_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.I"
        threat_id = "2147707581"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%DOWNLOADERON%" wide //weight: 1
        $x_1_2 = "%STARTUPON%" wide //weight: 1
        $x_1_3 = "%PERSISTANCEON%" wide //weight: 1
        $x_1_4 = "%ITSELFINJECTION%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_J_2147708924_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.J"
        threat_id = "2147708924"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 73 00 63 00 72 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "sn*x*hk.d*l*l" wide //weight: 1
        $x_1_3 = "\\Update.lnk" wide //weight: 1
        $x_1_4 = "\\*@&\\*&@" wide //weight: 1
        $x_1_5 = "*/***C {*0*}* *& *{*1*}*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Subti_L_2147711487_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.L"
        threat_id = "2147711487"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 45 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 1, accuracy: High
        $x_1_2 = "injection" ascii //weight: 1
        $x_1_3 = "Mexecute" ascii //weight: 1
        $x_1_4 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 ?? ?? 72 00 65 00 67 00 61 00 73 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Subti_M_2147711624_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.M"
        threat_id = "2147711624"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"{0}\" /v" wide //weight: 1
        $x_1_2 = "\"{2}\" /f" wide //weight: 1
        $x_1_3 = "\"{1}\" /d" wide //weight: 1
        $x_1_4 = {4d 00 65 00 74 00 61 00 6c 00 6c 00 69 00 63 00 61 00 ?? ?? 4c 00 6f 00 61 00 64 00 ?? ?? 48 00 4b 00 45 00 59 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Client\\WdiServiceHost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_N_2147712136_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.N"
        threat_id = "2147712136"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiDump" wide //weight: 1
        $x_1_2 = "AntiSandboxie" wide //weight: 1
        $x_1_3 = "DisableCMD" wide //weight: 1
        $x_1_4 = "DisableSafeMode" wide //weight: 1
        $x_1_5 = "DisableSystemRestore" wide //weight: 1
        $x_1_6 = "DisableTaskManager" wide //weight: 1
        $x_1_7 = "PersistenceStartup" wide //weight: 1
        $x_1_8 = "ProtectionAntiMemory" wide //weight: 1
        $x_1_9 = "ProtectionBSOD" wide //weight: 1
        $x_1_10 = "ProtectionDisableUAC" wide //weight: 1
        $x_1_11 = "StartupForceRestart" wide //weight: 1
        $x_1_12 = "StartupMelt" wide //weight: 1
        $x_1_13 = "ZoneIDDelete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule VirTool_MSIL_Subti_O_2147718580_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.O!bit"
        threat_id = "2147718580"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Options.UACBypass" wide //weight: 1
        $x_1_2 = "Options.CheckSandbox" wide //weight: 1
        $x_1_3 = "3f7a7afa-00b0-4887-8938-7d43bd09ba71" wide //weight: 1
        $x_1_4 = "/c start eventvwr" wide //weight: 1
        $x_1_5 = "lvotgso.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Subti_P_2147724751_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.P!bit"
        threat_id = "2147724751"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 47 07 08 72 ?? ?? 00 70 6f ?? 00 00 0a 5d 91 08 1b 58 07 8e 69 58 1f 1f 5f 63 20 ?? 00 00 00 5f d2 61 d2 52 08 17 58 0c 07 00 06 08 8f ?? 00 00 01}  //weight: 5, accuracy: Low
        $x_1_2 = {00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 67 65 74 5f 4c 65 6e 67 74 68 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_Q_2147725133_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.Q!bit"
        threat_id = "2147725133"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Antirunners" ascii //weight: 1
        $x_1_2 = "NativeFunctions" ascii //weight: 1
        $x_1_3 = "CriticalProcess" ascii //weight: 1
        $x_1_4 = {16 0a 2b 10 00 03 06 03 06 91 1f 20 61 d2 9c 00 06 17 58 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_R_2147725166_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.R!bit"
        threat_id = "2147725166"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 28 1d 00 00 0a 6a 0a 20 ?? ?? ?? 00 28 04 00 00 0a 00 28 1d 00 00 0a 6a 0b 07 06 59 20 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "The Wireshark Network Analyzer" wide //weight: 1
        $x_1_3 = "SbieDll.dll" wide //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = {49 00 6e 00 6a 00 00 0d 69 00 74 00 73 00 65 00 6c 00 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Subti_S_2147727003_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.S!bit"
        threat_id = "2147727003"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@RANDOM@.exe" wide //weight: 1
        $x_1_2 = "%BINDERON%" wide //weight: 1
        $x_1_3 = "\\@RANDOM@.lnk" wide //weight: 1
        $x_1_4 = "%ITSELFINJECTION%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Subti_U_2147733819_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.U!bit"
        threat_id = "2147733819"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OlpvbmUuSWRlbnRpZmllcg==" ascii //weight: 1
        $x_1_2 = "XCNiaW5kbmFtZSMuZXhl" ascii //weight: 1
        $x_1_3 = "I2JpbmRfc2V0dCM=" ascii //weight: 1
        $x_1_4 = "L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsICI=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Subti_V_2147734297_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Subti.V!bit"
        threat_id = "2147734297"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Subti"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AddBindedFiled" ascii //weight: 1
        $x_1_2 = "FilePersistance" ascii //weight: 1
        $x_1_3 = "MonitoringSelf" ascii //weight: 1
        $x_1_4 = "RegPersistance" ascii //weight: 1
        $x_1_5 = "ReclaimMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


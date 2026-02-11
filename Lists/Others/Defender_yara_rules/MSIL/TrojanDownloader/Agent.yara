rule TrojanDownloader_MSIL_Agent_A_2147576562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.A"
        threat_id = "2147576562"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\system32\\Microsoft\\System.exe" wide //weight: 1
        $x_1_2 = "\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_3 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "explorer http://messenger.msn.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Agent_K_2147651077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.K"
        threat_id = "2147651077"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WhiteNet.Http" ascii //weight: 1
        $x_1_2 = "obzor.ru/up.huy" wide //weight: 1
        $x_1_3 = "safesurf.txt" wide //weight: 1
        $x_1_4 = "account?mode=url&cmd=start&loc=autosurf" wide //weight: 1
        $x_1_5 = "surfguart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_MSIL_Agent_Q_2147654872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.Q"
        threat_id = "2147654872"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 64 6f 74 6e 65 74 5c 67 61 69 62 61 6e 5c [0-64] 73 64 62 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "SPOOLSVC" wide //weight: 1
        $x_1_3 = ".bcloud.me:8080/webCloud/" wide //weight: 1
        $x_1_4 = "KHTML, like Gecko" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Agent_AA_2147745047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.AA"
        threat_id = "2147745047"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VigenereDecrypt" ascii //weight: 1
        $x_1_2 = "TDesDecrypt" ascii //weight: 1
        $x_1_3 = "Base64_Encode" ascii //weight: 1
        $x_1_4 = "VernamDecrypt" ascii //weight: 1
        $x_1_5 = "//pastebin.com/raw/" ascii //weight: 1
        $x_1_6 = "aHR0cHM6Ly9wYXN0ZWJpbi5jb20v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Agent_ME_2147799595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.ME!MTB"
        threat_id = "2147799595"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Test-NetConnection -TraceRoute" ascii //weight: 1
        $x_1_2 = "https://store2.gofile.io/download/" ascii //weight: 1
        $x_1_3 = "Debug" ascii //weight: 1
        $x_1_4 = "Hello" ascii //weight: 1
        $x_1_5 = "twitter.com" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "powershell" ascii //weight: 1
        $x_1_8 = "GetString" ascii //weight: 1
        $x_1_9 = "Replace" ascii //weight: 1
        $x_1_10 = "DownloadData" ascii //weight: 1
        $x_1_11 = "Invoke" ascii //weight: 1
        $x_1_12 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Agent_JPG_2147806145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.JPG!MTB"
        threat_id = "2147806145"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://buysrilankan.lk/k/ConsoleApp17.jpeg" wide //weight: 1
        $x_1_2 = {00 52 65 76 65 72 73 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "AhO4aFg0ca" wide //weight: 1
        $x_1_5 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Agent_MH_2147806286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.MH!MTB"
        threat_id = "2147806286"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "srktksskasfd" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "Encoding" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "Invoke" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
        $x_1_10 = "Replace" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Agent_MI_2147806287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.MI!MTB"
        threat_id = "2147806287"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bootstrapper" wide //weight: 1
        $x_1_2 = "Downloadshitweneed" ascii //weight: 1
        $x_1_3 = "dxdiag.txt" wide //weight: 1
        $x_1_4 = "https://aka.ms/vs/16/release/vc_redist.x86.exe" wide //weight: 1
        $x_1_5 = "/install /quiet /norestart" wide //weight: 1
        $x_1_6 = "dxdwebsetup.exe" wide //weight: 1
        $x_1_7 = "Taraniyor..." wide //weight: 1
        $x_1_8 = "Kill" ascii //weight: 1
        $x_1_9 = "SkipVerification" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
        $x_1_11 = "Reverse" ascii //weight: 1
        $x_1_12 = "GOLD Fixed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Agent_MA_2147808548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.MA!MTB"
        threat_id = "2147808548"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 06 72 01 00 00 70 72 ?? 00 00 70 6f 16 00 00 0a 00 02 7b 05 00 00 04 6f 17 00 00 0a 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 [0-3] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 52 6f 61 6d 69 6e 67 [0-3] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "PleaseWait.exe" ascii //weight: 1
        $x_1_7 = "C:\\Users\\PC\\Desktop\\PleaseWait\\PleaseWait\\obj\\Debug\\PleaseWait.pdb" ascii //weight: 1
        $x_1_8 = "Form1_Load" ascii //weight: 1
        $x_1_9 = "does not work on your computer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_MSIL_Agent_MC_2147808549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.MC!MTB"
        threat_id = "2147808549"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 46 00 69 00 6c 00 65 00 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-96] 2f 46 69 6c 65 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = {16 2c 46 26 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 72 ae 00 00 70 14 6f ?? ?? ?? 0a 17 2d 2f 26 d0 ?? 00 00 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 14 17 8d ?? 00 00 01 25 16 07 a2 6f ?? ?? ?? 0a 74 ?? 00 00 1b 2b 06 0a 2b b8 0b 2b cf 2a}  //weight: 1, accuracy: Low
        $x_1_4 = "ShowWindow" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = "GetString" ascii //weight: 1
        $x_1_8 = "Invoke" ascii //weight: 1
        $x_1_9 = "FromBase64" ascii //weight: 1
        $x_1_10 = "GetTypes" ascii //weight: 1
        $x_1_11 = "Debug" ascii //weight: 1
        $x_1_12 = "powershell" ascii //weight: 1
        $x_1_13 = "Test-NetConnection -TraceRoute" ascii //weight: 1
        $x_1_14 = "WriteLine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

rule TrojanDownloader_MSIL_Agent_EUA_2147819923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.EUA!MTB"
        threat_id = "2147819923"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://z.zz.fo/sWqKO.bin" wide //weight: 1
        $x_1_2 = "/SoundService/test.exe" wide //weight: 1
        $x_1_3 = "BalCheck.exe" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "$f9195372-f40f-458a-8738-9a7097870157" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Agent_SPQ_2147838222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Agent.SPQ!MTB"
        threat_id = "2147838222"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 08 1f 1a 28 ?? ?? ?? 0a 72 81 00 00 70 09 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 1f 1a 28 ?? ?? ?? 0a 72 37 00 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 de 0e}  //weight: 2, accuracy: Low
        $x_1_2 = "Users\\Nisha\\Desktop\\Cracked PasteBin - 1337\\Cracked PasteBin\\obj\\Debug\\Setup.pdb" ascii //weight: 1
        $x_1_3 = "Cracked_PasteBin.My" ascii //weight: 1
        $x_1_4 = "Cracked_PasteBin.Resources" wide //weight: 1
        $x_1_5 = "WindowsServices\\WindowsServices.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


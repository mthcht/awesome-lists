rule Trojan_Win64_Stealer_O_2147841133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.O!MSR"
        threat_id = "2147841133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_2 = "Microsoft\\Edge\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_3 = "Browser\\User Data\\Local State" ascii //weight: 1
        $x_1_4 = "ImBetter.pdb" ascii //weight: 1
        $x_1_5 = "password:" ascii //weight: 1
        $x_1_6 = "ChromeCookies" ascii //weight: 1
        $x_1_7 = "BraveCookies" ascii //weight: 1
        $x_1_8 = "TitanCookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_PADB_2147900956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.PADB!MTB"
        threat_id = "2147900956"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files (x86)\\Windows Defender\\MpHeadlessRun.exe" ascii //weight: 1
        $x_1_2 = "Application added to startup successfully." ascii //weight: 1
        $x_1_3 = "Make sure to run the program with administrator privileges" ascii //weight: 1
        $x_1_4 = "stealer\\x64\\Release\\stealer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SO_2147902568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.SO!MTB"
        threat_id = "2147902568"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PuffierIndus" ascii //weight: 2
        $x_2_2 = "GuldenRuche for Windows" ascii //weight: 2
        $x_2_3 = "GuldenRuche" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_RP_2147911246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.RP!MTB"
        threat_id = "2147911246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 50 50 44 41 54 41 00 5c 68 74 64 6f 63 73 5c 00 00 00 00 00 00 00 00 5c 6f 75 74 70 75 74 2e 65 78 65 00 5c 00 00 00 43 3a 5c 00 44 3a 5c 00 45 3a 5c 00 46 3a 5c 00 47 3a 5c 00 48 3a 5c 00 49 3a 5c 00 5a 3a 5c}  //weight: 1, accuracy: High
        $x_1_2 = "\\ConsoleApplication1.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_WZ_2147918410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.WZ!MTB"
        threat_id = "2147918410"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runtime.stealWork" ascii //weight: 1
        $x_1_2 = "/Desktop/Stealer/main.go" ascii //weight: 1
        $x_1_3 = "Go build ID: " ascii //weight: 1
        $x_1_4 = "h1:H+t6A/QJMbhCSEH5rAuRxh+CtW96g0Or0Fxa9IKr4uc=" ascii //weight: 1
        $x_1_5 = "main.reverseString" ascii //weight: 1
        $x_1_6 = "type:.eq.main.Response" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_GD_2147929221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.GD!MTB"
        threat_id = "2147929221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "88.119.167.239" ascii //weight: 5
        $x_1_2 = "qulonglong" ascii //weight: 1
        $x_1_3 = "remove_me_from_pool" ascii //weight: 1
        $x_1_4 = "bot2world_connected" ascii //weight: 1
        $x_1_5 = "bot2world_ready_read" ascii //weight: 1
        $x_1_6 = "bot2server_connected" ascii //weight: 1
        $x_1_7 = "bot2server_ready_read" ascii //weight: 1
        $x_1_8 = "\\Shell\\Open\\Command" ascii //weight: 1
        $x_1_9 = "KeyboardModifier" ascii //weight: 1
        $x_1_10 = "mailto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SUN_2147934104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.SUN!MTB"
        threat_id = "2147934104"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 f5 69 0c 00 48 83 7b 18 08 48 89 7b 10 72 05 48 8b 0b eb 03 48 8b cb 33 c0 66 89 04 79 48 8b 7c 24 30 48 8b 74 24 40 48 8b c3 48 8b 5c 24 38}  //weight: 1, accuracy: High
        $x_1_2 = "/svcstealer/get.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_MX_2147936682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.MX!MTB"
        threat_id = "2147936682"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 39 c8 0f 84 17 94 09 00 66 89 10 0f b7 50 0a 48 83 c0 02 66 85 d2}  //weight: 1, accuracy: High
        $x_1_2 = "Runtine Broker.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_MX_2147936682_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.MX!MTB"
        threat_id = "2147936682"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 79 53 65 63 72 65 74 4c 6f 61 64 65 72 4b 65 79 31 32 33 00 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 43 00 3a 00 5c 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 56 00 4d 00 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_NS_2147940059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.NS!MTB"
        threat_id = "2147940059"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {44 89 16 45 31 d2 4c 89 c6 49 89 d1 eb dc 0f b6 48 06 0f b7 40 04 35 65 b1 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {88 4a 06 66 89 42 04 4c 8d ac 24 f8 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_NS_2147940059_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.NS!MTB"
        threat_id = "2147940059"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 da e8 9b bf ff ff 41 83 f8 01 0f 94 c0 eb 02 31 c0 c7 45 c8 03 00 00 00 88 45 cc 48 8d 55 c8 48 89 f9 ff 56 20 8b 45 c8 48 8b 4d f8 87 01 a8 04}  //weight: 2, accuracy: High
        $x_1_2 = {28 48 8d 6a 40 48 8d 4d f0 e8 88 40 ff ff 90 48 83 c4 28 5e 5d c3 48 89 54 24 10 55 56 48 83 ec 28 48 8d 6a 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_GVA_2147941530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.GVA!MTB"
        threat_id = "2147941530"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 0f b6 d1 40 32 d6 0f b6 c8 d2 fa 49 c1 e8 ?? 42 8b 4c 84 ?? f6 c2 01 8b d0}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 4c 24 58 43 88 0c 2f 41 ff c7 45 3b fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_NFA_2147942380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.NFA!MTB"
        threat_id = "2147942380"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\wallet_dump_%s" ascii //weight: 1
        $x_1_2 = "encrypted_key" ascii //weight: 1
        $x_2_3 = "Credentials/Microsoft_Mail.txt" ascii //weight: 2
        $x_1_4 = "Software\\Microsoft\\Office\\%s\\Outlook\\Profiles\\Outlook" ascii //weight: 1
        $x_1_5 = "BraveWallet" ascii //weight: 1
        $x_1_6 = "Exodus" ascii //weight: 1
        $x_1_7 = "%s\\katz_ontop.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_NR_2147942888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.NR!MTB"
        threat_id = "2147942888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stealWork" ascii //weight: 2
        $x_2_2 = "ProcSteal" ascii //weight: 2
        $x_1_3 = "hangupkilledlistensocket" ascii //weight: 1
        $x_1_4 = "killing Cmdexe" ascii //weight: 1
        $x_1_5 = "destroy" ascii //weight: 1
        $x_1_6 = "bad restart PC" ascii //weight: 1
        $x_1_7 = "GetUserProfileDirectory" ascii //weight: 1
        $x_1_8 = "Bot/New/Launcher" ascii //weight: 1
        $x_1_9 = "GetSystemInfo" ascii //weight: 1
        $x_1_10 = "saveInfoFromPath" ascii //weight: 1
        $x_1_11 = "targetpc" ascii //weight: 1
        $x_1_12 = "remote address changed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_TGZ_2147944028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.TGZ!MTB"
        threat_id = "2147944028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c1 48 8b 8c 24 b8 ab 00 00 66 89 01 8b 84 24 68 1a 00 00 48 8b 8c 24 50 48 00 00 48 8b 49 08 8b 94 24 98 71 00 00 48 8b bc 24 00 e4 00 00 0f b6 04 08 88 04 17 8b 84 24 ?? ?? ?? ?? ff c0 89 84 24 ?? ?? ?? ?? 8b 84 24 54 7e 00 00 8b 8c 24 d8 71 00 00 2b c8 8b c1 89 84 24 a8 71 00 00 8b 84 24 20 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_NK_2147945420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.NK!MTB"
        threat_id = "2147945420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 44 24 ?? 48 89 84 24 ?? 00 00 00 48 8b 8c 24 ?? 00 00 00 e8 ?? ?? 00 00 48 89 84 24 ?? 00 00 00 48 8b 8c 24 ?? 00 00 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {48 8d 8c 24 ?? 00 00 00 e8 ?? ?? 00 00 48 8d 8c 24 ?? 00 00 00 e8 ?? ?? 00 00 48 8d 8c 24 ?? 00 00 00 e8 ?? ?? 00 00 e9 e3 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Telegram Desktop" ascii //weight: 1
        $x_1_4 = "Roaming" ascii //weight: 1
        $x_1_5 = "USERPROFILE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_NL_2147945529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.NL!MTB"
        threat_id = "2147945529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 05 52 63 28 00 45 31 c9 48 83 c0 18 0f 1f 00 4c 8b 00 4c 39 c3 72 13 48 8b 50 08 8b 52 08 49 01 d0 4c 39 c3 0f 82 88 00 00 00 41 83 c1 01 48 83 c0 28 41 39 f1 75 d8}  //weight: 2, accuracy: High
        $x_1_2 = {48 89 c7 48 85 c0 0f 84 e6 00 00 00 48 8b 05 05 63 28 00 48 8d 1c b6 48 c1 e3 03 48 01 d8 48 89 78 20 c7 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SX_2147949161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.SX!MTB"
        threat_id = "2147949161"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 85 00 13 00 00 85 c0 74 3f 44 8b c0 c6 84 05 a0 02 00 00 00 48 8d 95 a0 02 00 00 48 8d 8d f0 00 00 00 e8 ?? ?? ?? ?? 4c 8d 8d 00 13 00 00 41 b8 ff 0f 00 00 48 8d 95 a0 02 00 00 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 2, accuracy: Low
        $x_1_2 = "\\steam\\Token.txt" ascii //weight: 1
        $x_1_3 = "\\Pc_info.txt" ascii //weight: 1
        $x_1_4 = "\\\\.\\pipe\\ChromeDecryptIPC_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SXA_2147950174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.SXA!MTB"
        threat_id = "2147950174"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 40 3c 48 8b 4c 24 30 48 03 c8 48 8b c1 48 89 44 24 50 b8 ?? ?? ?? ?? 48 6b c0 ?? 48 8b 4c 24 50}  //weight: 5, accuracy: Low
        $x_2_2 = "VoidRAT" ascii //weight: 2
        $x_2_3 = "WinHTTP Uploader/1.0" ascii //weight: 2
        $x_1_4 = "american" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SXB_2147950176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.SXB!MTB"
        threat_id = "2147950176"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 44 24 48 49 83 fe ?? 49 0f 47 c3 42 0f b7 0c 40 8d 41 d0 66 83 f8 ?? 76 17 8d 41 bf 66 83 f8 ?? 76 0e 66 83 e9 ?? 66 83 f9 ?? 0f 87 ?? ?? ?? ?? 49 ff c0 4c 3b c2 72 c6}  //weight: 5, accuracy: Low
        $x_2_2 = "USDT hijack" ascii //weight: 2
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "GetKeyState" ascii //weight: 1
        $x_1_5 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_AB_2147951433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.AB!MTB"
        threat_id = "2147951433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 33 c5 48 8b 6c 24 30 48 33 c6 48 8b 74 24 38 48 83 f0 ad 0f b6 c0 49 33 c6 48 8b d0 48 d3 ea 41 8b c8 48 d3 e0 40 0f b6 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


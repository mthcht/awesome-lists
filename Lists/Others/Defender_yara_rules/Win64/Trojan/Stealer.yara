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
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 ff c8 48 85 c0 7c ?? 4c 8b 84 24 ?? ?? ?? ?? 4c 39 c0 0f 83 ?? ?? ?? ?? 48 ff c3 4c 8b 84 24 ?? ?? ?? ?? 45 0f b6 04 00 48 39 d9 73}  //weight: 3, accuracy: Low
        $x_2_2 = {4c 89 d3 48 89 f9 bf ?? ?? ?? ?? 48 8d 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 49 89 da 49 89 c1 48 89 cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SXB_2147950176_1
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

rule Trojan_Win64_Stealer_MK_2147952112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.MK!MTB"
        threat_id = "2147952112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 8d 71 01 0f b6 3c 38 48 39 d6 ?? ?? 48 89 44 24 58 40 88 7c 24 43 48 89 4c 24 78}  //weight: 15, accuracy: Low
        $x_10_2 = {48 ff c3 0f 1f 00 48 83 fb 0a ?? ?? 48 8d 34 0a 48 01 de 48 83 fe ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_ZVB_2147952228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.ZVB!MTB"
        threat_id = "2147952228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Global\\OmegaStealer_v2_Mutex" wide //weight: 5
        $x_2_2 = "discordcanary/Local Storage/leveldb" ascii //weight: 2
        $x_2_3 = "Opera Software/Opera Stable/Local Storage/leveldb" ascii //weight: 2
        $x_2_4 = "Google/Chrome/User Data/Default/Local Storage/leveldb" ascii //weight: 2
        $x_2_5 = "Yandex/YandexBrowser/User Data" ascii //weight: 2
        $x_2_6 = "Vivaldi/User Data" ascii //weight: 2
        $x_2_7 = "Microsoft/Edge/User Data" ascii //weight: 2
        $x_2_8 = "Telegram Desktop/tdata" ascii //weight: 2
        $x_2_9 = "VBoxMouse.sys" ascii //weight: 2
        $x_2_10 = "VBoxGuest.sys" ascii //weight: 2
        $x_2_11 = "vmhgfs.sys" ascii //weight: 2
        $x_2_12 = "vmmouse.sys" ascii //weight: 2
        $x_2_13 = "vmci.sys" ascii //weight: 2
        $x_2_14 = "vmsrvc.sys" ascii //weight: 2
        $x_1_15 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_16 = "SELECT host_key, name, encrypted_value FROM cookies" ascii //weight: 1
        $x_1_17 = "SOFTWARE\\WOW6432Node\\Valve\\Steam" ascii //weight: 1
        $x_1_18 = "Cookies.txt" ascii //weight: 1
        $x_1_19 = "--- RUNNING PROCESSES ---" ascii //weight: 1
        $x_1_20 = "system_summary.txt" ascii //weight: 1
        $x_1_21 = "http://api.ipify.org" ascii //weight: 1
        $x_1_22 = "wmic product get name,version" ascii //weight: 1
        $x_1_23 = "Discord_Tokens.txt" ascii //weight: 1
        $x_1_24 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_25 = "screenshot.png" ascii //weight: 1
        $x_1_26 = "Passwords.txt" ascii //weight: 1
        $x_1_27 = "--- WIFI PASSWORDS ---" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_NPE_2147954586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.NPE!MTB"
        threat_id = "2147954586"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "t.me/BluelineStealer" ascii //weight: 2
        $x_1_2 = "cryptomonnaie" ascii //weight: 1
        $x_1_3 = "jbdaocneiiinmjbjlgal" ascii //weight: 1
        $x_1_4 = "hnfanknocfeofbddgcij" ascii //weight: 1
        $x_1_5 = "hpglfhgfnhbgpjdenjgm" ascii //weight: 1
        $x_1_6 = "armazenamento_de_chaves" ascii //weight: 1
        $x_1_7 = "electrum" ascii //weight: 1
        $x_1_8 = "%LOCALAPPDATA%\\Comodo\\Dragon\\User Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SXD_2147955239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.SXD!MTB"
        threat_id = "2147955239"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b c2 66 89 45 ?? 69 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2b c8 48 8b c3 66 89 4d ?? 69 c9 ?? ?? ?? ?? 2b ca 88 4c 05 ?? 48 ff c0 48 83 f8}  //weight: 3, accuracy: Low
        $x_2_2 = {0f b6 0c 13 8b c1 83 e1 ?? 48 c1 e8 ?? 8a 44 04 48 88 44 55 ?? 8a 44 0c 48 88 44 55 91 48 ff c2 48 83 fa}  //weight: 2, accuracy: Low
        $x_1_3 = "Google\\Chrome\\User Data\\Local State" ascii //weight: 1
        $x_1_4 = "BraveSoftware\\Brave-Browser\\User Data\\Local State" ascii //weight: 1
        $x_1_5 = "Microsoft\\Edge\\User Data\\Local State" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_MPZ_2147955849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.MPZ!MTB"
        threat_id = "2147955849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 14 08 48 8b 8c 24 ?? 02 00 00 e8 34 05 00 00 8b 8c 24 ?? 01 00 00 48 03 c1 48 89 84 24 60 02 00 00 48 8b 84 24 60 02 00 00 0f b6 00 83 f0 36 48 8b 8c 24 60 02 00 00 88 01 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_PWT_2147956511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.PWT!MTB"
        threat_id = "2147956511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c3 0f b6 c3 8b d8 48 8d 4d ?? 48 03 c8 0f b6 11 8d 04 32 0f b6 f0 0f b6 44 35 ?? 88 01 88 54 35 ?? 0f b6 01 03 c2 0f b6 c0 0f b6 4c 05 ?? 30 0f 48 8d 7f 01 49 83 e8 01 75 c5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SXC_2147957714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.SXC!MTB"
        threat_id = "2147957714"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8b 44 24 40 03 c1 89 44 24 40 8b 44 24 40 2b c2 89 44 24 40 8b 44 24 40 35 ?? ?? ?? ?? 89 44 24 40 ff c2 83 c1}  //weight: 6, accuracy: Low
        $x_4_2 = {14 01 60 cf c7 84 24 ?? ?? ?? ?? 3a cc 64 0d c7 84 24 ?? ?? ?? ?? d5 3c 42 48 c7 84 24 ?? ?? ?? ?? 41 48 d6 6a c7 84 24 ?? ?? ?? ?? 4e 79 16 57 c7 84 24 ?? ?? ?? ?? 0e 0c 20 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_AHC_2147957749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.AHC!MTB"
        threat_id = "2147957749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Chrome:Crypto.com DeFi Wallet" ascii //weight: 10
        $x_20_2 = "Chrome:Jaxx Liberty" ascii //weight: 20
        $x_30_3 = "Installed antivirus programs : %s" ascii //weight: 30
        $x_40_4 = "Crypto wallet browser extensions :" ascii //weight: 40
        $x_50_5 = "Atomic Wallet" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_MKA_2147959469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.MKA!MTB"
        threat_id = "2147959469"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {90 0f 57 c0 0f 11 45 2f 0f 57 c9 f3 0f 7f 4d 3f 48 8d 55 0f 48 83 7d 27 07 48 0f 47 55 0f 4c 8b 45 1f 48 8d 4d 2f}  //weight: 25, accuracy: High
        $x_5_2 = "[DEBUG] Decrypted Key Address: 0x%p" ascii //weight: 5
        $x_5_3 = "DEBUG] Failed To Fetch Key" ascii //weight: 5
        $x_5_4 = "[DEBUG] Unsupported browser" ascii //weight: 5
        $x_5_5 = "chrome.exe" ascii //weight: 5
        $x_5_6 = "whale.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


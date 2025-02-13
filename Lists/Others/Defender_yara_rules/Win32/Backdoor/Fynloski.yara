rule Backdoor_Win32_Fynloski_F_2147633745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.F"
        threat_id = "2147633745"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MUTEXNAME" ascii //weight: 1
        $x_1_2 = "SERVDNAME" ascii //weight: 1
        $x_1_3 = "ACTIVXNAME" ascii //weight: 1
        $x_1_4 = "ANTIVM" ascii //weight: 1
        $x_1_5 = "MELT" ascii //weight: 1
        $x_1_6 = "GETMSNINFO" ascii //weight: 1
        $x_1_7 = "#botCommand%Mass" ascii //weight: 1
        $x_1_8 = "InYourAss" ascii //weight: 1
        $x_1_9 = "GetSIN" ascii //weight: 1
        $x_1_10 = "RemoteErrorError on kill process" ascii //weight: 1
        $x_1_11 = "RemoteErrorError on Run file as admin" ascii //weight: 1
        $x_15_12 = {80 fb 31 75 0d 8d ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 fb 32 75 0d 8d ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 fb 33 75 0d 8d ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 fb 34 75 0d 8d ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 fb 35 75 0d}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Fynloski_A_2147640184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.A"
        threat_id = "2147640184"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "DCPERSFWBP" ascii //weight: 3
        $x_3_2 = {49 5f 41 4d 5f 44 54 09 00 [0-25] 4b 6c 6f 67 2e 64 61 74}  //weight: 3, accuracy: Low
        $x_1_3 = {68 24 59 47 00 68 34 59 47 00 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {68 fc 52 47 00 68 0c 53 47 00 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {5a 59 59 64 89 10 68 30 58 47 00}  //weight: 1, accuracy: High
        $x_1_6 = {5a 59 59 64 89 10 68 4d 52 47 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Fynloski_A_2147640184_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.A"
        threat_id = "2147640184"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 06 83 f8 2e 0f 8f ?? ?? 00 00 0f 84 ?? ?? 00 00 83 c0 f8 83 f8 25 0f 87 ?? ?? 00 00 ff 24}  //weight: 2, accuracy: Low
        $x_2_2 = {81 7d a4 de ca de 43 0f 85}  //weight: 2, accuracy: High
        $x_2_3 = {c6 04 18 e9 8b 4d ?? 8b c1 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 83 c0 01 83 d2 00 2b f1 83 ee 05}  //weight: 2, accuracy: Low
        $x_2_4 = {68 7f 74 04 40 8b 45 fc 50 e8 ?? ?? ?? ?? 40 0f 84 ?? ?? 00 00 8b 45 f8 b9 4c 00 00 00 99 f7 f9 48 85 c0 0f 8c}  //weight: 2, accuracy: Low
        $x_2_5 = "#botCommand%" ascii //weight: 2
        $x_1_6 = "PortScanAdd" ascii //weight: 1
        $x_1_7 = "RPCLanScan" ascii //weight: 1
        $x_1_8 = "WindowsLive:name=*" ascii //weight: 1
        $x_1_9 = "DDOSHTTPFLOOD" ascii //weight: 1
        $x_1_10 = "DDOSSYNFLOOD" ascii //weight: 1
        $x_1_11 = "DDOSUDPFLOOD" ascii //weight: 1
        $x_1_12 = "ActiveOfflineKeylogger" ascii //weight: 1
        $n_10_13 = "Comet RAT Legacy is already active in your system" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Fynloski_K_2147685042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.K"
        threat_id = "2147685042"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#BOT#VisitUrl" ascii //weight: 1
        $x_1_2 = "#BOT#OpenUrl" ascii //weight: 1
        $x_1_3 = "#BOT#Ping" ascii //weight: 1
        $x_1_4 = "#BOT#RunPrompt" ascii //weight: 1
        $x_1_5 = "#BOT#CloseServer" ascii //weight: 1
        $x_1_6 = "#BOT#SvrUninstall" ascii //weight: 1
        $x_1_7 = "#BOT#URLUpdate" ascii //weight: 1
        $x_1_8 = "#BOT#URLDownload" ascii //weight: 1
        $x_1_9 = "DDOSHTTPFLOOD" ascii //weight: 1
        $x_1_10 = "DDOSSYNFLOOD" ascii //weight: 1
        $x_1_11 = "DDOSUDPFLOOD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Fynloski_M_2147687071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.M"
        threat_id = "2147687071"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#BOT#VisitUrl" ascii //weight: 1
        $x_1_2 = "#BOT#OpenUrl" ascii //weight: 1
        $x_1_3 = "#BOT#SvrUninstall" ascii //weight: 1
        $x_1_4 = "#BOT#URLDownload" ascii //weight: 1
        $x_1_5 = "KILLREMOTESHELL" ascii //weight: 1
        $x_1_6 = {30 04 32 46 ff 4d ?? 43 81 e3 ff 00 00 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Fynloski_A_2147690049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.gen!A!!Fynloski.gen!A"
        threat_id = "2147690049"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Fynloski: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = "\\shkernel\\HelpdeskDataStructs.h" wide //weight: -100
        $n_50_2 = "GridinSoft LLC" wide //weight: -50
        $n_50_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 67 00 73 00 61 00 6d 00 2e 00 65 00 78 00 65 00}  //weight: -50, accuracy: High
        $x_1_4 = "#BOT#VisitUrl" ascii //weight: 1
        $x_1_5 = "#BOT#SvrUninstall" ascii //weight: 1
        $x_1_6 = "#BOT#URLDownload" ascii //weight: 1
        $x_1_7 = "KILLREMOTESHELL" ascii //weight: 1
        $x_1_8 = "ActiveOfflineKeylogger" ascii //weight: 1
        $x_1_9 = "DDOSUDPFLOOD" ascii //weight: 1
        $x_1_10 = "DDOSSYNFLOOD" ascii //weight: 1
        $x_1_11 = "DDOSHTTPFLOOD" ascii //weight: 1
        $x_1_12 = "RPCLanScan" ascii //weight: 1
        $x_1_13 = "PortScanAdd" ascii //weight: 1
        $x_1_14 = "activeremoteshell" ascii //weight: 1
        $x_1_15 = "#BOT#OpenUrl" ascii //weight: 1
        $x_1_16 = "#BOT#CloseServer" ascii //weight: 1
        $x_1_17 = "#BOT#URLUpdate" ascii //weight: 1
        $x_1_18 = "#BOT#RunPrompt" ascii //weight: 1
        $x_1_19 = "#RemoteScreenSize" ascii //weight: 1
        $x_1_20 = "#BOT#Ping" ascii //weight: 1
        $x_1_21 = {30 04 32 46 ff 4d ?? 43 81 e3 ff 00 00 80}  //weight: 1, accuracy: Low
        $x_2_22 = {8b 06 83 f8 2e 0f 8f ?? ?? 00 00 0f 84 ?? ?? 00 00 83 c0 f8 83 f8 25 0f 87 ?? ?? 00 00 ff 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Fynloski_R_2147696363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.R"
        threat_id = "2147696363"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiVirusDisableNotify" ascii //weight: 1
        $x_1_2 = "ActiveOnlineKeylogger" ascii //weight: 1
        $x_1_3 = "#SendClip" ascii //weight: 1
        $x_1_4 = "#FreezeIO" ascii //weight: 1
        $x_1_5 = "#BOT#VisitUrl" ascii //weight: 1
        $x_1_6 = "#BOT#OpenUrl" ascii //weight: 1
        $x_1_7 = "#BOT#Ping" ascii //weight: 1
        $x_1_8 = "#BOT#RunPrompt" ascii //weight: 1
        $x_1_9 = "#BOT#URLUpdate" ascii //weight: 1
        $x_1_10 = "#BOT#URLDownload" ascii //weight: 1
        $x_1_11 = "#BOT#CloseServer" ascii //weight: 1
        $x_1_12 = "#RemoteScreenSize" ascii //weight: 1
        $x_1_13 = "DDOSHTTPFLOOD" ascii //weight: 1
        $x_1_14 = "DDOSSYNFLOOD" ascii //weight: 1
        $x_1_15 = "DDOSUDPFLOOD" ascii //weight: 1
        $x_1_16 = "ACTIVEREMOTESHELL" ascii //weight: 1
        $n_100_17 = "Comet RAT Legacy is already active in your system" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (6 of ($x*))
}

rule Backdoor_Win32_Fynloski_N_2147723898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.N!bit"
        threat_id = "2147723898"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 0e 0f b6 c1 0f be 94 18 ?? ?? ?? ?? 8b 46 08 8b 75 fc 0f be 04 30 be ff 00 00 00 33 d0 8b c1 c1 f8 08 23 c6 2b d0 8b c1 c1 f8 10 23 c6 c1 e9 18 33 d0 2b d1 90 8b 45 fc 8b 75 08 88 14 38 40 89 45 fc 3b 46 10 7c b8}  //weight: 3, accuracy: Low
        $x_1_2 = {68 00 80 00 00 6a 00 53 ff 55 f8 8d 87 ?? ?? ?? ?? 89 45 08 ff 55 08}  //weight: 1, accuracy: Low
        $x_1_3 = {63 3a 5c 75 73 65 72 73 5c 67 67 67 61 73 5c 64 65 73 6b 74 6f 70 5c 73 64 73 73 64 65 65 77 5c [0-16] 5c 73 64 64 66 73 64 5c 72 65 6c 65 61 73 65 5c 73 64 64 66 73 64 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Fynloski_PA_2147742275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.PA!MTB"
        threat_id = "2147742275"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UDPFlood" ascii //weight: 1
        $x_1_2 = "SynFlood" ascii //weight: 1
        $x_1_3 = "HTTPFlood" ascii //weight: 1
        $x_1_4 = "Keylogger" ascii //weight: 1
        $x_1_5 = "RootKit" ascii //weight: 1
        $x_1_6 = "UntScreenCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Fynloski_AA_2147754737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fynloski.AA!MTB"
        threat_id = "2147754737"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fynloski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "JqZtFi0HBRKnt2QK2j4TyXVqb0zNWHWWUf.dll" ascii //weight: 1
        $x_1_2 = {89 ff 4b 75 fb 5f 00 6a 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 4b 75 f0 [0-79] bb ?? ?? ?? ?? 89 ff 4b 75 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


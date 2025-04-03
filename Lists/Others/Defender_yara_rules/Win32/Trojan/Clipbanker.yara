rule Trojan_Win32_Clipbanker_RF_2147779788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.RF!MTB"
        threat_id = "2147779788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ce 00 ff ff ff 46 8a 84 35 ?? ?? ?? ?? 88 84 3d ?? ?? ?? ?? 88 8c 35 ?? ?? ?? ?? 0f b6 84 3d ?? ?? ?? ?? 8b 4d ?? ?? ?? ?? 03 c2 0f b6 c0 8a 84 05 ?? ?? ?? ?? 30 04 19 41 89 4d ?? 3b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_RF_2147779788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.RF!MTB"
        threat_id = "2147779788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stfhklmopqyuhgljlkopydstre" ascii //weight: 1
        $x_1_2 = "CDlgQunFaSZ2" ascii //weight: 1
        $x_1_3 = "e:\\G_JJJ\\jjj2008\\root2017y11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_RF_2147779788_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.RF!MTB"
        threat_id = "2147779788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetStartupInfoA" ascii //weight: 1
        $x_1_2 = "GetCPInfo" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_5 = "GetSystemTimeAsFileTime" ascii //weight: 1
        $x_10_6 = "bc1q5lg2pvfu9fwdhrmc3mtem8vv05ea4xy347fhzh" ascii //weight: 10
        $x_10_7 = "3FmY1a8HEdMVunCA5decyhSVT3kn9dcNBp" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_MA_2147794521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.MA!MTB"
        threat_id = "2147794521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4c 24 38 8b 44 24 3c 0f ac c1 14 81 f9 00 08 00 00 0f 82 ?? ?? ?? ?? 0f 28 05 ?? ?? ?? ?? 33 c0 0f 11 04 24 c7 44 24 10 ?? ?? ?? ?? 8a 0c 24 30 4c 04 01 40 83 f8 12 72}  //weight: 5, accuracy: Low
        $x_2_2 = {6a 00 8d 4c 24 18 51 6a 18 8d 4c 24 24 51 6a 00 6a 00 68 00 00 07 00 50 ff 15}  //weight: 2, accuracy: High
        $x_1_3 = "GetTickCount64" ascii //weight: 1
        $x_1_4 = "GetClipboardData" ascii //weight: 1
        $x_1_5 = "CLIpU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_MA_2147794521_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.MA!MTB"
        threat_id = "2147794521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}" ascii //weight: 1
        $x_1_2 = "ltc1|[LM])[a-zA-HJ-NP-Z0-9]{26,40}" ascii //weight: 1
        $x_1_3 = "4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV" ascii //weight: 1
        $x_1_4 = "VBScript.RegExp" ascii //weight: 1
        $x_1_5 = "Runtime Explorer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_RW_2147795835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.RW!MTB"
        threat_id = "2147795835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitcoincash:" ascii //weight: 1
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "GetStartupInfoW" ascii //weight: 1
        $x_1_4 = "GetClipboardData" ascii //weight: 1
        $x_10_5 = "C:\\Users\\anast\\source\\repos\\cleaper\\Release\\cleaper.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_RWA_2147795836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.RWA!MTB"
        threat_id = "2147795836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetNativeSystemInfo" ascii //weight: 1
        $x_1_2 = "Wow64DisableWow64FsRedirection" ascii //weight: 1
        $x_1_3 = "ShellExecuteExW" ascii //weight: 1
        $x_1_4 = "GetKeyState" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExW" ascii //weight: 1
        $x_10_6 = "RunProgram=\"hidcon:cmd /c cmd < Pura.vssm" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_2147806238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.xyzw!MTB"
        threat_id = "2147806238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "xyzw: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 87 ac 47 ab 80 29 76 b3 66 f2 32 49 80 1d 90 91 3a 04 33 73 28}  //weight: 10, accuracy: High
        $x_10_2 = {d2 30 32 e9 28 16 09 9a 1d a4 17 a5 71 12}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_RTA_2147807769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.RTA!MTB"
        threat_id = "2147807769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c0 28 8b 80 ?? ?? ?? ?? 33 d2 f7 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 01 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_2147811342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.rrdh!MTB"
        threat_id = "2147811342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "rrdh: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetSystemInfo" ascii //weight: 1
        $x_1_2 = "GetTickCount" ascii //weight: 1
        $x_1_3 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "hVAxtyfwyfswtydfw" ascii //weight: 1
        $x_1_7 = "rTAsetrdfrwyueqe356_rtlsecurememroygAS" ascii //weight: 1
        $x_1_8 = "56_rtls%curememroygAS" ascii //weight: 1
        $x_1_9 = "rTAsetrdfrwyueqe356_r" ascii //weight: 1
        $x_1_10 = "YKWetrdfrw)0eq)266" ascii //weight: 1
        $x_1_11 = "fqe056_stlrnSwrXmemroygiW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_SPN_2147836053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.SPN!MTB"
        threat_id = "2147836053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0b 07 2c 4f 07 73 0c 00 00 0a 0c 03 18 73 0d 00 00 0a 0d 09 73 0e 00 00 0a 13 04 07 6f ?? ?? ?? 0a d4 8d 0f 00 00 01 13 05 07 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 26 11 04 11 05 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 2a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_AMBE_2147903807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.AMBE!MTB"
        threat_id = "2147903807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 33 ed 55 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 53 56 57 6a ?? ff 15 ?? ?? ?? ?? 8b d8 53 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_AMMF_2147906288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.AMMF!MTB"
        threat_id = "2147906288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 c1 88 45 17 66 0f 7e f0 32 c1 30 4d 36 88 45 27 48 8d 45 d8 49 ff c0 42 80 3c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_CCIB_2147907382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.CCIB!MTB"
        threat_id = "2147907382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 40 23 40 00 33 ff 6a 01 57 89 7d fc ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clipbanker_AMAG_2147919822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clipbanker.AMAG!MTB"
        threat_id = "2147919822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 6c 69 70 c7 45 ?? 62 6f 61 72 66 c7 45 ?? 64 00 c7 45 ?? 43 6c 6f 73 c7 45 ?? 65 43 6c 69 c7 45 ?? 70 62 6f 61 66 c7 45 ?? 72 64 c6 45 ?? 00 c6 45 ?? 00 c7 45 ?? 45 6d 70 74 c7 45 ?? 79 43 6c 69 c7 45 ?? 70 62 6f 61 66 c7 45 ?? 72 64}  //weight: 2, accuracy: Low
        $x_1_2 = {80 01 fd 8d 49 01 42 3b d7 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_Bladabindi_GG_2147787632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bladabindi.GG!MTB"
        threat_id = "2147787632"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 98 22 a8 82 b8 21 1d 63 bb 96 50 12 00 24 c8 e2 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bladabindi_AA_2147794183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bladabindi.AA!MTB"
        threat_id = "2147794183"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DecryptPassword" ascii //weight: 3
        $x_3_2 = "getMails func start" ascii //weight: 3
        $x_3_3 = "Goto killing outlook process" ascii //weight: 3
        $x_3_4 = "Aftker Sleeped" ascii //weight: 3
        $x_3_5 = "Debug.txt" ascii //weight: 3
        $x_3_6 = "russk18" ascii //weight: 3
        $x_3_7 = "getMails func returning" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bladabindi_LKL_2147805595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bladabindi.LKL!MTB"
        threat_id = "2147805595"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 eb 02 83 e9 04 8b 45 0c 8b 55 10 81 e0 ff 00 00 00 33 d2 8b 04 85 58 d1 63 00 89 01 8b 45 0c 8b 55 10 0f ac d0 08 c1 ea 08 89 45 0c 89 55 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bladabindi_ZA_2147901410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bladabindi.ZA!MTB"
        threat_id = "2147901410"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_2 = "CryptoStreamMode" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "HashAlgorithm" ascii //weight: 1
        $x_1_5 = "CompressShell" ascii //weight: 1
        $x_1_6 = "NtQueryInformationProcess" ascii //weight: 1
        $x_1_7 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_9 = "OutputDebugString" ascii //weight: 1
        $x_1_10 = "get_IsAttached" ascii //weight: 1
        $x_1_11 = "COR_ENABLE_PROFILING" wide //weight: 1
        $x_1_12 = "Profiler detected" wide //weight: 1
        $x_1_13 = "Debugger detected (Managed)" wide //weight: 1
        $x_1_14 = "Chrome.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


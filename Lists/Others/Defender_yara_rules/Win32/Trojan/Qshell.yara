rule Trojan_Win32_Qshell_MR_2147773470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qshell.MR!MTB"
        threat_id = "2147773470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 05 [0-4] 03 [0-2] 8b [0-2] 31 ?? 83 [0-3] 83 [0-3] 8b [0-2] 3b [0-2] 8b [0-2] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qshell_GKM_2147773604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qshell.GKM!MTB"
        threat_id = "2147773604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 8a a5 08 00 03 55 ?? 03 c2 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qshell_GKM_2147773604_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qshell.GKM!MTB"
        threat_id = "2147773604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 1e 23 00 00 e8 ?? ?? ?? ?? 83 c4 04 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 8c 10 ?? ?? ?? ?? 2b 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea 1e 23 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ac 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? b8 73 00 00 00 85 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qshell_RB_2147774346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qshell.RB!MTB"
        threat_id = "2147774346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 02 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 e0 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qshell_RT_2147793130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qshell.RT!MTB"
        threat_id = "2147793130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ea 18 64 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 2b d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qshell_RT_2147793130_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qshell.RT!MTB"
        threat_id = "2147793130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f1 bd 3a 0d ?? ?? ?? ?? 33 c0 89 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 3b 95 ?? ?? ?? ?? 7f ?? 0f be 0d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 31 0a 83 ?? ?? ?? ?? ?? 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


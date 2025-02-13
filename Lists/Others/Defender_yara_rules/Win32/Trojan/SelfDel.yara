rule Trojan_Win32_SelfDel_CL_2147805267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SelfDel.CL!MTB"
        threat_id = "2147805267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bd 38 a6 3f 7d 81 ed dd f2 9f 6c f7 dd 55 ff 0c 24 5d 81 f5 37 83 87 89 01 e8 5d 01 f0 2d 93 cf e7 66}  //weight: 1, accuracy: High
        $x_1_2 = {01 ee 66 81 f3 2f ec 01 eb 8b 1b 8b 1b 31 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SelfDel_TC_2147809808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SelfDel.TC!MTB"
        threat_id = "2147809808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 df 33 1d ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 83 eb 07 33 1d ?? ?? ?? ?? 89 5d e0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 81 c6 ?? ?? ?? ?? 83 f6 0f 03 f3 83 ee 41 33 f7 89 35}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SelfDel_BR_2147812207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SelfDel.BR!MTB"
        threat_id = "2147812207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 33 c8 33 c8 33 c8 33 c8 e9}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SelfDel_CB_2147814574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SelfDel.CB!MTB"
        threat_id = "2147814574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 f0 2b 35 [0-4] 81 f6 [0-4] 2b 75 08 33 f3 89 35 [0-4] 8b 7d 08 81 ef [0-4] e9}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 55 0c 33 d3 2b 15 [0-4] 83 f2 ?? 89 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SelfDel_A_2147828589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SelfDel.A!MTB"
        threat_id = "2147828589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 80 81 82 83 c6 45 f4 83 33 d2 39 08 0f 94 c2 23 f2 33 d2 39 08}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1c 08 80 f3 42 88 19 41 4a 75 f4 5b}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e2 02 2b fa 8a 97 ff f7 ff ff 81 ef 01 08 00 00 41 88 10 40 47 8a 17 88 10 8a 57 01 40 88 10 40 8a 51 fe}  //weight: 1, accuracy: High
        $x_1_4 = {83 7d 0c 23 66 c7 45 dc 5c 00 66 c7 45 de 4d 00 66 c7 45 e0 6f 00 66 c7 45 e2 7a 00 66 c7 45 e4 69 00 66 c7 45 e6 6c 00 66 c7 45 e8 6c 00 66 c7 45 ea 61 00 66 89 75 ec 66 c7 45 f0 2e 00 66 c7 45 f2 65 00 66 c7 45 f4 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SelfDel_MA_2147842623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SelfDel.MA!MTB"
        threat_id = "2147842623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "INFO_PC_CPUNAME" ascii //weight: 2
        $x_2_2 = "INFO_RANSOM_ID" ascii //weight: 2
        $x_1_3 = "Main.exe" ascii //weight: 1
        $x_1_4 = "dllstart" ascii //weight: 1
        $x_1_5 = "DllMain" ascii //weight: 1
        $x_1_6 = "&pc_name=" wide //weight: 1
        $x_1_7 = "&num_of_processors=" wide //weight: 1
        $x_1_8 = "://api.ipify.org/" wide //weight: 1
        $x_1_9 = "uid=%s&mac=%s&crc=%s&time=%s" wide //weight: 1
        $x_1_10 = "cmd /c ping 127.0.0.1 -n 1 > nul & del" wide //weight: 1
        $x_1_11 = "-k DcomLaunch -p" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SelfDel_GZA_2147901971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SelfDel.GZA!MTB"
        threat_id = "2147901971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 f8 3b 4a 18 7d ?? 8b 5d fc 8b 1c 8b 03 5d 08 ff 75 0c 53 e8 ?? ?? ?? ?? 83 f8 01 74 03 41 eb ?? 8b 45 f8 8b 40 24 03 45 08 31 db 66 8b 1c 48 8b 45 f8 8b 40 1c 03 45 08 8b 04 98 03 45 08}  //weight: 10, accuracy: Low
        $x_1_2 = "open status d:\\\\edwr\\araf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


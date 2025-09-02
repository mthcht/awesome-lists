rule Trojan_Win64_ReverseShell_CCAG_2147889362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReverseShell.CCAG!MTB"
        threat_id = "2147889362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 85 10 02 00 00 48 89 45 ?? 48 8b 85 ?? ?? ?? ?? 48 89 45 48 ?? 8b 85 ?? ?? ?? ?? 48 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = "159.89.214.31" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReverseShell_ARS_2147908374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReverseShell.ARS!MTB"
        threat_id = "2147908374"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 95 d0 0f 00 00 b8 00 00 00 00 b9 1e 00 00 00 48 89 d7 f3 48 ab 48 89 fa 89 02 48 83 c2 04}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 85 b0 13 00 00 8b 48 0c 48 8b 85 b0 13 00 00 8b 50 08 48 8b 85 b0 13 00 00 8b 40 04 41 89 c8 89 c1}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 85 b0 13 00 00 48 8b 40 10 89 c1 48 8b 85 b0 13 00 00 48 8b 50 20 48 8b 85 b8 13 00 00 41 89 c8 48 89 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReverseShell_YAA_2147916450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReverseShell.YAA!MTB"
        threat_id = "2147916450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3_reverse_shell_undetect\\x64\\Release\\3_reverse_shell_undetect.pdb" ascii //weight: 1
        $x_1_2 = {c7 85 10 02 00 00 31 39 32 2e 48 8d 95 e0 01 00 00 c7 85 14 02 00 00 31 36 38 2e 48 8d 8d 10 02 00 00 c7 85 18 02 00 00 38 2e 31 30 f3 0f 7f 45 20 66 c7 85 1c 02 00 00 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 85 b0 02 00 00 43 72 65 61 48 8b c8 c7 85 b4 02 00 00 74 65 50 72 48 8b d8 c7 85 b8 02 00 00 6f 63 65 73 66 c7 85 bc 02 00 00 73 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReverseShell_YAB_2147916451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReverseShell.YAB!MTB"
        threat_id = "2147916451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2_app_reverseshell\\x64\\Release\\2_app_reverseshell.pdb" ascii //weight: 1
        $x_1_2 = "2_app_reverseshell, Version 1.0" wide //weight: 1
        $x_1_3 = "MY2APPREVERSESHELL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReverseShell_HNB_2147922784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReverseShell.HNB!MTB"
        threat_id = "2147922784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 72 65 70 72 5f 5f 72 65 76 39 35 73 68 65 6c 6c 5f 75}  //weight: 2, accuracy: High
        $x_1_2 = {00 54 4d 5f 5f 62 51 38 39 62 61 74 33 68 55 6b 6d 4a 42 34 68 56 68 37 39 62 66 34 77 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReverseShell_PAGI_2147934757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReverseShell.PAGI!MTB"
        threat_id = "2147934757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 99 f7 7d 28 89 d0 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10}  //weight: 2, accuracy: High
        $x_2_2 = "ATTACKER_IP" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReverseShell_SX_2147946572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReverseShell.SX!MTB"
        threat_id = "2147946572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 89 ea 48 c7 44 24 20 00 00 00 00 4d 89 e1 ff 15 ?? ?? ?? ?? 48 8b 1d ?? ?? ?? ?? 4c 89 e9 ff d3 31 c0 b9 1a 00 00 00 48 89 ef f3 ab c7 44 24 70 68 00 00 00 ff 15}  //weight: 15, accuracy: Low
        $x_15_2 = {45 31 c9 45 31 c0 4c 89 f1 48 89 c2 48 8d 44 24 70 4c 89 64 24 48 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15}  //weight: 15, accuracy: High
        $x_10_3 = {31 f6 48 8b 7c 24 58 b9 7e 00 00 00 45 31 c9 48 89 f0 41 b8 00 04 00 00 48 89 ea 48 c7 84 24 d0 02 00 00 00 00 00 00 f3 48 ab 4c 89 f1 48 c7 84 24 d8 02 00 00 00 00 00 00 ff 15}  //weight: 10, accuracy: High
        $x_5_4 = "%s_%08X.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReverseShell_AR_2147951147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReverseShell.AR!MTB"
        threat_id = "2147951147"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 45 50 48 89 45 48 48 8b 45 48 48 89 45 40 48 8d 05 ?? ?? ?? ?? 48 8d 55 d0 48 89 54 24 48 48 8d 55 f0 48 89 54 24 40 48 c7 44 24 38 00 00 00 00}  //weight: 10, accuracy: Low
        $x_5_2 = {48 8d ac 24 80 00 00 00 e8 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 48 89 85 ?? 02 00 00 c7 85 ?? 02 00 00 5c 11 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


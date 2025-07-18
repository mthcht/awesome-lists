rule Trojan_Win64_AsyncRAT_DO_2147844103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.DO!MTB"
        threat_id = "2147844103"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 98 0f b6 44 05 a0 83 f0 63 89 c2 8b 85 [0-4] 48 98 88 54 05 a0 83 85 [0-4] 01 8b 85 [0-4] 3d 01 73 01 00 76}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_A_2147850690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.A!MTB"
        threat_id = "2147850690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 04 01 48 89 84 24 ?? ?? ?? ?? 48 63 4c 24 ?? 33 d2 48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 48 0f be 84 04 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 8d 8c 24}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 48 8b 8c 24 ?? ?? ?? ?? 48 33 c8 48 8b c1 48 63 4c 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_B_2147890066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.B!MTB"
        threat_id = "2147890066"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 00 48 98 0f b6 44 05 a0 83 f0 ?? 89 c2 8b 85 cc ?? 01 00 48 98 88 54 05 a0 83 85 cc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_C_2147890442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.C!MTB"
        threat_id = "2147890442"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 30 04 03 48 ff c0 48 39 c7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_ARA_2147902716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.ARA!MTB"
        threat_id = "2147902716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 45 e8 48 89 c1 48 83 c0 01 48 89 45 e8 eb d9 48 8b 45 e8 48 8b 4d f0 48 01 c1 48 8b 45 e8 48 8b 55 10 48 01 c2 0f be 02 8b 55 18 31 d0 88 01 eb cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_ARA_2147902716_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.ARA!MTB"
        threat_id = "2147902716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KDF62DFJFJFF26J.bat" ascii //weight: 2
        $x_2_2 = "taskkill /F /im svchost.exe" ascii //weight: 2
        $x_3_3 = "\\DiscordNukeBot\\x64\\Release\\1.pdb" ascii //weight: 3
        $x_3_4 = "\\sharescreen\\x64\\Release\\sharescreen.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_AsyncRAT_CK_2147903582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.CK!MTB"
        threat_id = "2147903582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 98 0f b6 94 05 ?? ?? ?? 00 8b 85 ?? ?? ?? 00 48 98 0f b6 84 05 ?? ?? ?? 00 31 c2 8b 85 ?? ?? ?? 00 48 98 88 94 05 ?? ?? ?? 00 83 85 ?? ?? ?? 00 01 8b 85 ?? ?? ?? 00 48 98 48 3d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_SA_2147905611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.SA!MTB"
        threat_id = "2147905611"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 01 83 fa ?? 0f 47 c8 49 ff c1 0f b6 d1 2b da 8b c2 83 c8 ?? c1 c3 ?? 0f af c2 8d 04 40 33 d8 49 83 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_KAJ_2147907244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.KAJ!MTB"
        threat_id = "2147907244"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 88 45 ?? eb e2 0f b6 45 ?? 48 63 c0 48 8b 4d ?? 48 01 c1 0f b6 45 ?? 48 63 c0 48 8b 55 ?? 48 01 c2 0f b6 01 48 89 4d f0 0f b6 0a 31 c8 48 8b 4d f0 88 01 eb c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_CM_2147907598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.CM!MTB"
        threat_id = "2147907598"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {37 80 74 24 ?? 38 80 74 24 ?? 39 80 74 24 ?? 3a 80 74 24 ?? 3b 80 74 24 ?? 3c 80 74 24 ?? 3d 34 3e c6 44 24 ?? 31 88 44 24 ?? 48 8d 44 24 ?? 49 ff c0 42 80 3c 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_ARAZ_2147934750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.ARAZ!MTB"
        threat_id = "2147934750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 45 f8 48 01 d0 0f b6 00 83 f0 55 89 c2 48 8d 0d ?? ?? 0c 00 48 8b 45 f8 48 01 c8 88 10 48 83 45 f8 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRAT_ARAX_2147935042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.ARAX!MTB"
        threat_id = "2147935042"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c2 42 32 04 09 88 04 29 80 c2 05 41 ff c0 4c 8b 0f 41 8b c8 48 8b 47 08 49 2b c1 48 3b c8 72 de}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 c2 42 32 04 09 88 04 29 80 c2 05 41 ff c0 4c 8b 0f 48 8b 47 08 49 2b c1 41 8b c8 48 3b c8 72 de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AsyncRAT_NA_2147946753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRAT.NA!MTB"
        threat_id = "2147946753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 54 24 68 48 89 94 24 b0 00 00 00 48 c7 84 24 c8 00 00 00 08 00 00 00 48 8d 15 a1 66 02 00 48 89 94 24 c0 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {4c 8d 0d e4 5e 02 00 4c 89 8c 24 f0 00 00 00 48 89 94 24 08 01 00 00 4c 89 84 24 00 01 00 00 48 8d 05 e5 63 02 00 bb 07 00 00 00 48 8d 8c 24 f0 00 00 00 bf 02 00 00 00 48 89 fe e8 b6 b3 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


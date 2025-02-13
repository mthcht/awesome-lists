rule Ransom_Win32_Snake_V_2147754583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snake.V!MTB"
        threat_id = "2147754583"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 08 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 89 4c 24 ?? 8d 54 24 ?? 89 14 24 8d 15 ?? ?? ?? ?? 89 54 24 ?? c7 44 24 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 8b 54 24 ?? 8b 5c 24 ?? 31 ed 39 d5 7d ?? 0f b6 34 2b 39 c5 73 ?? 83 c6 ?? 0f b6 3c 29 31 fe 83 fd ?? 96 88 44 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 7c 24 34 89 e6 e8 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 0c 24 89 44 24 ?? e8 ?? ?? ?? ?? 0f b6 44 24 ?? 84 c0 0f 84 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 8b 0c 24 c7 04 24 ?? ?? ?? ?? 89 4c 24 ?? 89 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 89 0c 24 89 54 24 ?? 89 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Snake_GO_2147754600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snake.GO!MTB"
        threat_id = "2147754600"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "systemfunction036" ascii //weight: 1
        $x_1_2 = "cryptacquirecontext" ascii //weight: 1
        $x_1_3 = "ImpersonateSelf" ascii //weight: 1
        $x_1_4 = "CryptGenRandom" ascii //weight: 1
        $x_1_5 = "NetUserGetInfo" ascii //weight: 1
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_50_7 = "Go build ID: \"SPlES9E155q_V-b330Fx/" ascii //weight: 50
        $x_50_8 = "Go build ID: \"X6lNEpDhc_qgQl56x4du/" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Snake_A_2147756865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snake.A"
        threat_id = "2147756865"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 96 88 ?? ?? ?? 96 45 39 ?? 7d 18 0f b6 34 2b [0-5] 39 ?? 73 [0-5] 0f b6 3c 29 31 fe [0-6] 72 df eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


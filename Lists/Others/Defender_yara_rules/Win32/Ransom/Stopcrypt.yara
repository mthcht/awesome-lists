rule Ransom_Win32_Stopcrypt_PAE_2147820032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.PAE!MTB"
        threat_id = "2147820032"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 31 4d fc 8b 45 fc 01 05 ?? ?? ?? ?? 2b 75 fc 83 0d ?? ?? ?? ?? ff 8b ce c1 e1 ?? 03 4d e8 8b c6 c1 e8 ?? 03 45 e0 8d 14 33 33 ca 33 c8 2b f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAI_2147851074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAI!MTB"
        threat_id = "2147851074"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8b 55 f4 33 45 ec 81 c3 ?? ?? ?? ?? 8b 4d dc 2b f0 89 45 f8 89 75 fc 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAI_2147851074_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAI!MTB"
        threat_id = "2147851074"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 03 44 24 ?? 03 cf 33 c2 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d7 31 54 24 0c 8b 44 24 0c 29 44 24 10 8d 44 24 20 e8 ?? ?? ?? ?? ff 4c 24 18 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAB_2147851085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAB!MTB"
        threat_id = "2147851085"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 04 24 8b 44 24 ?? 31 04 24 8b 04 24 8b 4c 24 08 89 01 59}  //weight: 1, accuracy: Low
        $x_10_2 = {8b 4c 24 18 8d 34 17 d3 ea 03 d5 8b fa 8b 54 24 10 8d 04 1a 33 c6 81 3d ?? ?? ?? ?? 21 01 00 00 89 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAC_2147851160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAC!MTB"
        threat_id = "2147851160"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 18 8d 34 17 d3 ea 8b 4c 24 10 8d 04 19 33 c6 03 d5 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b fa 89 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 04 24 00 00 00 00 8b 44 24 10 89 04 24 8b 44 24 0c 31 04 24 8b 04 24 8b 4c 24 ?? 89 01 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAD_2147852304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAD!MTB"
        threat_id = "2147852304"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 14 8b 44 24 10 33 cb 33 c1 89 44 24 10 2b f0 8b 44 24 24 29 44 24 18 ff 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 c1 e8 05 03 44 24 ?? 03 cd 33 c1 8b 4c 24 ?? 03 ce 33 c1 2b f8 8b d7 c1 e2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAE_2147853101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAE!MTB"
        threat_id = "2147853101"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 dc 01 45 fc 8b 45 f4 8b 4d f8 8d 14 01 8b 4d f0 d3 e8 03 45 d8 33 c2 31 45 fc 2b 7d fc 8b 45 d4 29 45 f8 ff 4d ec 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAF_2147887396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAF!MTB"
        threat_id = "2147887396"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 dc 01 45 f8 8b 4d f0 8b 45 f4 8b d3 d3 ea 03 c3 03 55 ?? 33 d0 31 55 f8 2b 7d f8 89 7d ec 8b 45 e0 29 45 f4 ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAG_2147893965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAG!MTB"
        threat_id = "2147893965"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 8b c8 c1 ea 05 03 54 24 ?? c1 e1 04 03 4c 24 ?? 03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f5 31 74 24 ?? 8b 44 24 ?? 29 44 24 14 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAH_2147899025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAH!MTB"
        threat_id = "2147899025"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 10 33 c6 89 44 24 10 8b 44 24 18 31 44 24 10 2b 7c 24 10 81 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stopcrypt_YAJ_2147906083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stopcrypt.YAJ!MTB"
        threat_id = "2147906083"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stopcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 03 45 ?? 89 45 ?? 8b 45 f8 89 45 ec 8b 45 f4 01 45 fc 8b 45 fc 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win32_DharmaCrypt_PA_2147795388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.PA!MTB"
        threat_id = "2147795388"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\info.hta" wide //weight: 1
        $x_1_2 = "\\FILES ENCRYPTED.txt" wide //weight: 1
        $x_1_3 = "\\Private.harma" wide //weight: 1
        $x_1_4 = "vssadmin Delete Shadows /All /Quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_MP_2147811099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.MP!MTB"
        threat_id = "2147811099"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 11 0f b6 45 ff 0f b6 4d f7 03 c1 0f b6 c0 8b 4d f0 0f b6 04 01 33 d0 8b 4d 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_YAA_2147900199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.YAA!MTB"
        threat_id = "2147900199"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a c3 32 44 24 17 85 d2 8b 4c 24 20 8b 74 24 20 0f b6 c0 0f b6 c9 0f 45 c8 8b 44 24 28 88 0c 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_YAB_2147903594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.YAB!MTB"
        threat_id = "2147903594"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 85 c0 0f 45 ca 89 0d 5c 55 43 00 8a 85 7c fa ff ff 30 85 8b fa ff ff 39 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_YAB_2147903594_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.YAB!MTB"
        threat_id = "2147903594"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 2b 45 ?? 8b 1d ?? ?? ?? ?? 0f af c7 0f af 45 ?? 03 c1 8a d0 32 55 ?? 88 54 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_YAC_2147906638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.YAC!MTB"
        threat_id = "2147906638"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 54 8a 44 24 27 8b 4c 24 3c 8b 7c 24 4c 8b 2d ?? ?? ?? ?? 32 c3 03 5c 24 5c 88 01 8b 44 24 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_YAC_2147906638_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.YAC!MTB"
        threat_id = "2147906638"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 01 8b 8d ?? ?? ?? ?? 8d 3c 49 8d 14 7a f7 da 03 d0 0f af ca}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 85 a8 fe ff ff 33 85 f4 fe ff ff 8b 95 4c ff ff ff 89 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_MKV_2147913204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.MKV!MTB"
        threat_id = "2147913204"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 42 34 8b 4d f4 89 41 38 8b 55 f4 8b 45 f4 8b 4a 1c 33 48 38 8b 55 f4 89 4a 3c 8b 45 f4 83 c0 20 89 45 f4 e9 72 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_YAD_2147913504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.YAD!MTB"
        threat_id = "2147913504"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 8d 57 b6 ff ff 8b 95 7c b6 ff ff 32 ca 8b bd 94 b6 ff ff 03 95 64 b6 ff ff 89 95 7c b6 ff ff 88 0c 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_YAE_2147913735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.YAE!MTB"
        threat_id = "2147913735"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 14 38 8d 3c 82 89 7d d4 8a c3 32 45 0f 88 45 0f 0f b7 4d d8 0f b7 45 a4 0f af c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DharmaCrypt_YAF_2147918358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DharmaCrypt.YAF!MTB"
        threat_id = "2147918358"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DharmaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 15 30 0b 44 00 0f b6 45 e3 33 45 d8 88 45 eb 8b 4d c8 3b 4d 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_EmotetCrypt_PB_2147773427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetCrypt.PB!MTB"
        threat_id = "2147773427"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 03 c8 48 63 05 ?? ?? ?? ?? 48 03 c8 48 63 05 ?? ?? ?? ?? 48 2b c8 48 63 05 ?? ?? ?? ?? 48 2b c8 48 8b 44 ?? ?? 0f b6 04 08 03 44 24 30 41 8b d0 33 d0 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EmotetCrypt_PB_2147773427_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetCrypt.PB!MTB"
        threat_id = "2147773427"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d0 33 c9 0f 1f 40 00 66 0f 1f 84 [0-6] 0f 10 81 ?? ?? ?? ?? 0f 28 ca 66 0f ef c8 0f 11 89 ?? ?? ?? ?? 0f 10 81 ?? ?? ?? ?? 0f 28 ca 66 0f ef c8 0f 11 89 ?? ?? ?? ?? 0f 10 81 ?? ?? ?? ?? 0f 28 ca 66 0f ef c8 0f 11 89 ?? ?? ?? ?? 0f 10 81 f8 b9 43 00 0f 28 ca 66 0f ef c8 0f 11 89 ?? ?? ?? ?? 83 c1 ?? 81 f9 ?? ?? ?? ?? 7c a1 81 f9 ?? ?? ?? ?? 7d ?? 8d 81 ?? ?? ?? ?? 0f 1f 00 80 30 ?? 40 3d ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
        $x_1_2 = "KILLER1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EmotetCrypt_AD_2147817191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetCrypt.AD!MTB"
        threat_id = "2147817191"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 c9 48 2b c1 48 63 0d ?? ?? ?? ?? 48 2b c1 48 8b 4c 24 ?? 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca 2b 0d ?? ?? ?? ?? 48 63 c9 48 8b 54 24 ?? 88 04 0a e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EmotetCrypt_AG_2147817528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetCrypt.AG!MTB"
        threat_id = "2147817528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 4c 24 ?? 41 8a 14 08 48 8b 4c 24 ?? 32 14 08 49 8b c3 b9 [0-80] 4c 63 df 48 c1 e0 ?? 4c 89 5c 24 ?? 48 2b c8 48 0f af cb 48 8d 04 0e 48 ff c6 4a 8d 0c b0 48 8b 44 24 ?? 48 89 74 24 ?? 88 14 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EmotetCrypt_AH_2147817779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetCrypt.AH!MTB"
        threat_id = "2147817779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 4c 89 c2 48 29 c2 48 8b 45 ?? 48 01 d0 0f b6 00 8b 55 ?? 29 d0 44 31 c8 88 01 83 45}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EmotetCrypt_GG_2147825418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetCrypt.GG!MTB"
        threat_id = "2147825418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {0f b6 84 04 a0 ?? ?? ?? 89 44 24 60 8b 44 24 30 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? 00 0f b6 04 01 8b 4c 24 60 33 c8 8b c1}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EmotetCrypt_TS_2147825439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetCrypt.TS!MTB"
        threat_id = "2147825439"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {0f b6 44 04 50 89 84 24 dc 0c ?? ?? 8b 84 24 50 0c ?? ?? 99 83 e2 ?? 03 c2 83 e0 ?? 2b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 dc 0c ?? ?? 33 c8 8b c1}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EmotetCrypt_PS_2147825854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EmotetCrypt.PS!MTB"
        threat_id = "2147825854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8b cb 4d 8d 40 01 f7 eb c1 fa ?? ff c3 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 43 32 4c 01 ff 41 88 48 ff 48 ff cf}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


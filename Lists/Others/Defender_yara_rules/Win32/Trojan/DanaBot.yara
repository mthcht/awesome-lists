rule Trojan_Win32_DanaBot_GM_2147754953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.GM!MTB"
        threat_id = "2147754953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3e b8 01 00 00 00 29 85 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 3b f3 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_GL_2147754954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.GL!MTB"
        threat_id = "2147754954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 57 c0 33 c8 66 0f 13 05 [0-48] 81 3d [0-53] 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_GL_2147754954_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.GL!MTB"
        threat_id = "2147754954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d6 33 ca 81 3d [0-21] c7 05 [0-21] 89 1d [0-21] 89 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 85 d8 f7 ff ff 8b 4d fc 89 78 04 5f 89 30 5e 33 cd 5b e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AG_2147755287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AG!MTB"
        threat_id = "2147755287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d3 33 ca 81 3d [0-37] c7 05 [0-37] 89 2d [0-37] 89 2d [0-37] 89 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 38 89 78 04 [0-16] 89 18 5b 83 c4 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AH_2147755435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AH!MTB"
        threat_id = "2147755435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 2b f0 [0-37] 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 [0-96] 31 44 24 [0-64] 03 54 24 ?? 89 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AK_2147755490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AK!MTB"
        threat_id = "2147755490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 ea ?? 03 95 ?? ?? ?? ?? 89 95 [0-37] 31 85 ?? ?? ?? ?? 2b bd [0-37] 29 85 ?? ?? ?? ?? ff 8d [0-37] 8b 85 ?? ?? ?? ?? 8b 4d ?? 89 38 [0-32] 89 58 ?? 33 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AV_2147756477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AV!MTB"
        threat_id = "2147756477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 33 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d e0 8b 55 ?? 89 14 01 [0-16] 8b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_GB_2147756565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.GB!MTB"
        threat_id = "2147756565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 37 4e}  //weight: 1, accuracy: High
        $x_1_2 = {8a 18 88 10 88 19 0f b6 00 0f b6 cb 03 c1 [0-48] 23 c6 8a 80 [0-37] 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_GC_2147756566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.GC!MTB"
        threat_id = "2147756566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b7 59 e7 1f f7 65 ?? 8b 45 ?? 81 45 [0-48] 81 ad [0-48] 81 45 [0-32] 8b 85 ?? ?? ?? ?? 30 0c 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_GF_2147756567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.GF!MTB"
        threat_id = "2147756567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 30 04 31 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d [0-16] 83 7d [0-16] 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_GJ_2147756746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.GJ!MTB"
        threat_id = "2147756746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 18 88 10 88 1e 0f b6 00 0f b6 d3 03 c2 23 c1 [0-37] 8a 80 [0-48] 33 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_GK_2147756808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.GK!MTB"
        threat_id = "2147756808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3e 56 [0-37] 83 c4 ?? 8b f0 3b f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AB_2147756810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AB!MTB"
        threat_id = "2147756810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 33 cd c1 e8 ?? 03 44 24 ?? 89 44 24 ?? 89 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 5c 24 ?? 8b 44 24 [0-64] ff 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AD_2147756812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AD!MTB"
        threat_id = "2147756812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3e 56 [0-48] 83 c4 [0-32] 8b f0 85 f6 [0-200] 8b 8d [0-64] 33 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AD_2147756812_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AD!MTB"
        threat_id = "2147756812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crowded4.dll" ascii //weight: 1
        $x_1_2 = "ServiceMain" ascii //weight: 1
        $x_1_3 = "TMethodImplementationIntercept" ascii //weight: 1
        $x_1_4 = "ShellExecuteExW" wide //weight: 1
        $x_1_5 = "PgZNTPgXQTp" wide //weight: 1
        $x_1_6 = "C:\\myself.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AE_2147756813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AE!MTB"
        threat_id = "2147756813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 33 ce c1 e8 ?? 03 44 24 ?? 89 44 24 ?? 89 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 5c 24 ?? 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AF_2147756885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AF!MTB"
        threat_id = "2147756885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f1 0f 57 c0 8b cf 66 0f 13 05 [0-32] c1 e1 ?? 03 ca 33 c8 81 3d [0-32] 89 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 20 8b 8c 24 ?? ?? ?? ?? 89 38 [0-48] 5f 5e [0-48] 89 68 [0-48] 5d 5b [0-48] 33 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AP_2147756962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AP!MTB"
        threat_id = "2147756962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 03 bc 24 [0-48] 0f 57 c0 81 3d [0-48] 66 0f 13 05 [0-48] 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AQ_2147756963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AQ!MTB"
        threat_id = "2147756963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 57 c0 66 0f 13 05 [0-48] 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 33 85 ?? ?? ?? ?? 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AS_2147757481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AS!MTB"
        threat_id = "2147757481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 57 c0 66 0f 13 05 [0-32] 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 33 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AT_2147757547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AT!MTB"
        threat_id = "2147757547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 83 25}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 60 8b 55 ?? 89 14 01 5b 83 c5 ?? 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AU_2147757725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AU!MTB"
        threat_id = "2147757725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 57 c0 66 0f 13 05 [0-21] 8b 55 ?? 03 55 ?? 89 55 ?? 8b 45 ?? 33 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AW_2147757726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AW!MTB"
        threat_id = "2147757726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 0f 57 c0 81 3d [0-32] 66 0f 13 05 [0-16] 89 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AZ_2147758028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AZ!MTB"
        threat_id = "2147758028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce 30 01 b8 [0-48] 83 f0 ?? 83 ad [0-48] 39 bd [0-32] [0-32] 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AX_2147758029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AX!MTB"
        threat_id = "2147758029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f3 33 75 ?? 89 7d ?? 29 75 ?? 25 ?? ?? ?? ?? 81 6d [0-48] bb ?? ?? ?? ?? 81 45 [0-48] 8b 45 ?? 8b 4d ?? 8b d0 d3 e2 8b c8 c1 e9 ?? 03 4d ?? 03 55 ?? 89 3d ?? ?? ?? ?? 33 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_AY_2147758030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.AY!MTB"
        threat_id = "2147758030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e0 8b cf c1 e9 ?? 03 4d ?? 03 45 ?? 03 d7 33 c1 33 c2 29 45 ?? a1 [0-32] c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_BA_2147758768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.BA!MTB"
        threat_id = "2147758768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff 8a 09 88 08 eb ?? 81 3d ?? ?? ?? ?? 32 09 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_BA_2147758768_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.BA!MTB"
        threat_id = "2147758768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 31 b8 [0-32] 83 f0 ?? 83 ad [0-48] 39 bd [0-48] [0-32] 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_BB_2147759968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.BB!MTB"
        threat_id = "2147759968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 d3 e6 8b c8 c1 e9 ?? 03 4d ?? 03 75 ?? 89 15 ?? ?? ?? ?? 33 f1 8b 4d ?? 03 c8 33 f1 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_BC_2147760046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.BC!MTB"
        threat_id = "2147760046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 d3 e2 8b c8 c1 e9 ?? 03 4d ?? 03 55 ?? 89 3d ?? ?? ?? ?? 33 d1 8b 4d ?? 03 c8 33 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_NEAA_2147837969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.NEAA!MTB"
        threat_id = "2147837969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "wrtpsdfhlzcvbnm" ascii //weight: 5
        $x_5_2 = "qeyuioaqeyuioaqe" ascii //weight: 5
        $x_5_3 = "wscproxystub.dll" ascii //weight: 5
        $x_5_4 = "D:\\Builds\\Server\\64x\\Debug\\FS_Config\\Config.dat" ascii //weight: 5
        $x_5_5 = "hpfvuw73.dll" ascii //weight: 5
        $x_1_6 = "System.EnterpriseServices.Thunk.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_EM_2147850224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.EM!MTB"
        threat_id = "2147850224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mvd-k-tula.ru" ascii //weight: 1
        $x_1_2 = "KEYKEY05" ascii //weight: 1
        $x_1_3 = "C:\\Galax6K\\dobaloc.exe" ascii //weight: 1
        $x_1_4 = "MessageBeep" ascii //weight: 1
        $x_1_5 = "GetUserNameA" ascii //weight: 1
        $x_1_6 = "WSAStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_VQ_2147902677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.VQ!MTB"
        threat_id = "2147902677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 45 ab 8a 45 ab 04 9f 2c 1a 73 04 80 6d ab 20 a1 ?? ?? ?? ?? 8a 00 88 45 aa 8a 45 aa 04 9f 2c 1a 73 04 80 6d aa 20 a1 ?? ?? ?? ?? 8a 00 88 45 a9 8a 45 a9 04 9f 2c 1a 73 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_SPD_2147905601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.SPD!MTB"
        threat_id = "2147905601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4c 24 10 30 04 0e 83 ff 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DanaBot_CCJN_2147936884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DanaBot.CCJN!MTB"
        threat_id = "2147936884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 80 b8 ?? ?? ?? ?? 09 75 0a 8b 45 fc c6 80 ?? ?? ?? ?? 0f ff 45 fc 83 7d fc 20 75 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


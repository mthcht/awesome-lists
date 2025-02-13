rule Trojan_Win32_Bandit_DSK_2147742757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandit.DSK!MTB"
        threat_id = "2147742757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 ef ff ff c7 05 ?? ?? ?? ?? be d3 85 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {80 e3 c0 08 9d ea ef ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {e9 05 00 00 0f 84 ?? ?? ?? ?? ?? ?? 80 e2 fc c0 e2 04 08 95 e9 ef ff ff 83 ?? 2c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandit_YP_2147748135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandit.YP!MTB"
        threat_id = "2147748135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 81 c6 47 86 c8 61 ff 4c 24 1c 8b 4c 24 14 ?? ?? ?? ?? ?? ?? 8b 74 24 2c 89 3e 81 fa 6d 0a 00 00 75 06 00 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandit_MP_2147749276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandit.MP!MTB"
        threat_id = "2147749276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 56 ff 15 ?? ?? ?? ?? 8b 4c 24 70 8b 54 24 1c 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b f7 c1 ee 05 03 74 24 68 03 d9 03 d7 33 da 81 3d ?? ?? ?? ?? 72 07 00 00 75 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandit_GA_2147749288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandit.GA!MTB"
        threat_id = "2147749288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff 69 04 00 00 75 ?? 53 ff 15 ?? ?? ?? ?? 8b 45 08 8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b f7 7c ?? 5e 5b c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 82 03 00 00 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 8c 31 f5 d0 00 00 8b 15 ?? ?? ?? ?? 88 0c 32 46 3b f0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandit_DHB_2147750038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandit.DHB!MTB"
        threat_id = "2147750038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f7 2b ee 8b 44 24 ?? d1 6c 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 29}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f7 d3 e7 c1 ee 05 03 74 24 ?? 03 7c 24 ?? 33 f8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Bandit_DHC_2147750039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandit.DHC!MTB"
        threat_id = "2147750039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f8 8b 44 24 ?? d1 6c 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 61 01 00 00 5b 75 14 55 55 ff 15 ?? ?? ?? ?? 55 55 55 55 55 55 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 89 38 5f 89 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandit_GB_2147750169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandit.GB!MTB"
        threat_id = "2147750169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 73 ?? 81 3d ?? ?? ?? ?? 48 07 00 00 75 ?? c7 05 ?? ?? ?? ?? e6 ac 2e 92 8b 95 ?? ?? ?? ?? 52 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 08 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 01 89 8d ?? ?? ?? ?? 81 bd ?? ?? ?? ?? 1c 86 0d 00 7d ?? 81 bd ?? ?? ?? ?? 7c 87 02 00 75 ?? e8 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandit_GC_2147751363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandit.GC!MTB"
        threat_id = "2147751363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 7b 89 04 24 b8 f9 cd 03 00 01 04 24 83 2c 24 7b 8b 04 24 8a 04 08 88 04 0a 59 c3 0c 00 51 a1 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cb 89 44 24 10 8d 04 1f c1 e9 05 03 4c 24 3c 89 44 24 1c 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 44 24 1c 31 44 24 10 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


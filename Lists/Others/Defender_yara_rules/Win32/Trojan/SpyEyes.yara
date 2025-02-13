rule Trojan_Win32_SpyEyes_DSK_2147752768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEyes.DSK!MTB"
        threat_id = "2147752768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b da 83 e3 03 03 f8 8b 5c 9e 04 03 da 33 fb 2b cf ff 4d 08 75}  //weight: 2, accuracy: High
        $x_2_2 = {8b 11 2b 55 ?? 8b 45 0c 03 45 f8 89 10 8b 4d ?? 81 e1 ff 00 00 00 f7 d1 88 4d e8 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SpyEyes_PVS_2147753881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEyes.PVS!MTB"
        threat_id = "2147753881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 8d 34 07 e8 ?? ?? ?? ?? 30 06 b8 01 00 00 00 29 45 fc 83 7d fc 00 7d}  //weight: 2, accuracy: Low
        $x_2_2 = {30 04 3e b8 01 00 00 00 29 45 80 8b 75 80 3b f3 7d 05 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SpyEyes_PVK_2147754186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEyes.PVK!MTB"
        threat_id = "2147754186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 08 8b 4d fc 5f 5e 89 58 04 33 cd 5b e8 ?? ?? ?? ?? c9 c2 04 00 0c 00 8b 8d ?? fb ff ff 8b 85 ?? fb ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyEyes_RAA_2147754389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEyes.RAA!MTB"
        threat_id = "2147754389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 ca 03 c1 8b 4d ?? 25 ff 00 00 00 8a 80 ?? ?? ?? ?? 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyEyes_RAB_2147754405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEyes.RAB!MTB"
        threat_id = "2147754405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 ca 03 c1 8b 8c 24 ?? ?? ?? ?? 25 ff 00 00 00 8a 80 ?? ?? ?? ?? 5e 33 cc e8 ?? ?? ?? ?? 81 c4 30 08 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyEyes_RS_2147775409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEyes.RS!MTB"
        threat_id = "2147775409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c4 89 84 24 ?? ?? ?? ?? 81 fb 20 05 00 00 75 ?? c7 05 ?? ?? ?? ?? f6 51 9d a0 56 33 f6 3b de 7e ?? e8 ?? ?? ?? ?? 30 04 37 46 3b f3 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyEyes_RMA_2147799584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEyes.RMA!MTB"
        threat_id = "2147799584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 eb ?? 8b 45 ?? 05 f8 00 00 00 89 45 ?? 8b 4d ?? 51 e8 ?? ?? ?? ?? 83 c4 04 c7 45 ?? 00 00 00 00 eb ?? 8b 55 ?? 83 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyEyes_TA_2147809926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEyes.TA!MTB"
        threat_id = "2147809926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d2 fb 66 41 d3 cb 66 44 23 d8 44 31 2c 24 f9 41 5b 4d 63 ed f5 4d 03 c5 e9}  //weight: 1, accuracy: High
        $x_1_2 = {ed 4f 30 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


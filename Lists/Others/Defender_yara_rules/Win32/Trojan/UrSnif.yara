rule Trojan_Win32_UrSnif_RPX_2147831115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPX!MTB"
        threat_id = "2147831115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 8b 8d 68 fe ff ff 03 ce 2b c8 46 88 19 3b b5 6c fe ff ff 72 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPX_2147831115_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPX!MTB"
        threat_id = "2147831115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 d2 74 01 ea 31 1a 81 ee 01 00 00 00 68 21 34 a3 ec 58 81 c2 04 00 00 00 01 f8 39 ca 75 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPX_2147831115_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPX!MTB"
        threat_id = "2147831115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f8 8b 45 f8 8b 48 1c 89 4d f4 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 55 f4 89 45 fc 8b 45 fc 8b e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPX_2147831115_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPX!MTB"
        threat_id = "2147831115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 db 0f 84 50 00 00 00 56 89 2c 24 89 14 24 68 00 00 00 00 5a 01 c2 50 b8 00 00 00 00 01 d0 01 08 58 5a 83 ec 04 89 14 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPX_2147831115_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPX!MTB"
        threat_id = "2147831115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0d 8b 54 24 44 8b 44 24 1c 88 1c 02 eb 0b 8b 44 24 44 8b 4c 24 1c 88 04 08}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 4c 52 68 00 30 00 00 68 00 d0 02 00 56 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPH_2147831534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPH!MTB"
        threat_id = "2147831534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c1 31 37 47 81 e8 01 00 00 00 48 39 d7 75 e6 81 e9 01 00 00 00 [0-32] c3 8d 34 1e 01 c0 8b 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPH_2147831534_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPH!MTB"
        threat_id = "2147831534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 fc 0f be 02 89 45 f8 8b 4d 08 03 4d fc 51}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 53 8b 45 08 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 4d 08 88 19 5b 5d c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPM_2147831919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPM!MTB"
        threat_id = "2147831919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 fc 8a 02 0c 01 0f b6 c8 89 d8 99 f7 f9 0f b6 0e 01 c8 88 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPD_2147839383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPD!MTB"
        threat_id = "2147839383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 0f b6 c0 3a 4d 0f 75 22 8a 16 8b c8 23 c7 c1 e0 03 0f b6 d2 83 e1 1f 0b c2 46 0f b6 16 c1 e0 08 0b c2 46 05 08 08 00 00 eb 38 3a 4d fa 75 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPT_2147840486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPT!MTB"
        threat_id = "2147840486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 86 18 01 00 00 01 86 94 00 00 00 8b 46 5c 29 86 ac 00 00 00 8b 8e d4 00 00 00 8b 46 70 31 04 11 83 c2 04 8b 86 dc 00 00 00 01 46 70 8b 86 d0 00 00 00 83 f0 01 29 86 d8 00 00 00 8b 86 d8 00 00 00 01 46 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPO_2147841062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPO!MTB"
        threat_id = "2147841062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af 46 70 89 46 70 8b 8e b4 00 00 00 8b 46 68 31 04 0f 83 c7 04 8b 86 c0 00 00 00 01 46 68 8b 86 04 01 00 00 33 46 0c 2d ?? ?? ?? ?? 01 46 60 8b 86 b8 00 00 00 35 ?? ?? ?? ?? 0f af 86 9c 00 00 00 89 86 9c 00 00 00 8b 86 f4 00 00 00 31 86 80 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UrSnif_RPY_2147892275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrSnif.RPY!MTB"
        threat_id = "2147892275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrSnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 45 f0 8b 4d 00 8b c6 0d 00 02 00 00 81 e1 00 00 00 04 0f 44 c6 8b f0 8d 44 24 28 50 8b 45 e8 56 ff 75 ec 03 c3 50 ff 54 24 3c 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


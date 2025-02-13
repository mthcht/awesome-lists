rule Trojan_Win32_SpyStealer_AN_2147817212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AN!MTB"
        threat_id = "2147817212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 28 8b 55 08 03 55 fc 0f be 1a e8 [0-4] 33 d8 8b 45 08 03 45 fc 88 18 6a 00}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_AP_2147818497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AP!MTB"
        threat_id = "2147818497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 d2 f7 75 14 8b 45 08 0f be 34 10 68 [0-4] 68 [0-4] e8 [0-4] 83 c4 08 0f af f0 89 75 f4 8b 4d 0c 03 4d f8 8a 11 88 55 ff 0f b6 45 ff 33 45 f4 8b 4d 0c 03 4d f8 88 01 eb ac}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_AQ_2147818955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AQ!MTB"
        threat_id = "2147818955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4c 24 18 8b 44 24 18 31 44 24 10 2b 7c 24 10 68 [0-4] 8d 44 24 20 50 e8 [0-4] 83 6c 24 20 01 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {03 44 24 28 89 44 24 10 8b 44 24 18 03 44 24 1c 89 44 24 14 8b 54 24 14 31 54 24 10 8b cb c1 e9 05 03 cd}  //weight: 1, accuracy: High
        $x_2_3 = {81 44 24 24 e9 59 6c 17 81 44 24 7c 0e aa 3f 2c 81 44 24 10 1e c6 bf 46 81 ac 24 00 01 00 00 49 37 33 20 81 6c 24 34 88 91 28 52 81 44 24 40 ed a6 cf 5f 81 84 24 bc 00 00 00 bc c5 1f 54 81 ac 24 94 00 00 00 0e 83 20 39 81 ac 24 dc 00 00 00 ed 92 8b 29 81 04 24 46 e1 6e 70}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_AR_2147818959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AR!MTB"
        threat_id = "2147818959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 84 07 36 23 01 00 8b 0d [0-4] 88 04 0f 81 3d [0-4] 66 0c 00 00 75 0b}  //weight: 2, accuracy: Low
        $x_2_2 = {83 ff 26 75 05 e8 [0-4] 47 81 ff b7 c4 3d 00 7c ed}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_VM_2147819245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.VM!MTB"
        threat_id = "2147819245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 8d c0 fe ff ff 8b 55 08 83 c2 7c 89 95 38 fd ff ff 8b 45 08 83 c0 0f 89 45 90 8b 4d 08 83 c1 5d 89 8d bc fe ff ff 8b 55 08}  //weight: 10, accuracy: High
        $x_10_2 = {89 4d e8 8b 95 ?? ?? ?? ?? 0f af 55 e8 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 4d b4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_VP_2147819407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.VP!MTB"
        threat_id = "2147819407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7c ff ff ff 0f af 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 39 95 6c ff ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {0f af 75 88 89 b5 ?? ?? ?? ?? 8d b3 ?? ?? ?? ?? 0f af 75 d0 89 b5 ?? ?? ?? ?? 8d b3 ?? ?? ?? ?? 03 75 e4 39 7d c8 89 b5 ?? ?? ?? ?? 8d b3 ?? ?? ?? ?? 89 b5 48 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_AS_2147819643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AS!MTB"
        threat_id = "2147819643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 8b 45 ?? 31 18 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_AT_2147819735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AT!MTB"
        threat_id = "2147819735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 b9 04 00 00 00 f7 f1 a1 [0-4] 0f be 0c 10 8b 55 ec 0f b6 82 [0-4] 33 c1 8b 4d ec 88 81 [0-4] eb c2}  //weight: 2, accuracy: Low
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_VV_2147819741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.VV!MTB"
        threat_id = "2147819741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 0f be 34 10 e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 69 c6 ?? ?? ?? ?? 30 04 1f 43 eb}  //weight: 10, accuracy: Low
        $x_10_2 = {2e 00 00 00 c7 44 24 ?? 00 ?? 01 00 c7 44 24 ?? 20 30 4a 00 c7 04 24 fb ?? 4c 00 89 85 54 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_AU_2147819839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AU!MTB"
        threat_id = "2147819839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d8 31 d2 8d 8d [0-4] f7 75 14 8b 45 08 0f be 34 10 e8 [0-4] 8d 8d [0-4] e8 [0-4] 69 c6 4d 91 fc 09 30 04 1f 43 eb b5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_XV_2147820126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.XV!MTB"
        threat_id = "2147820126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be da 89 9d 4c ff ff ff ?? ?? 83 ca ?? 0f be da 89 9d ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 33 9d ?? ?? ?? ?? 69 db ?? ?? ?? ?? 89 9d ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_XZ_2147820218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.XZ!MTB"
        threat_id = "2147820218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 75 0c 3b 5d ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 d8 31 d2 f7 75 ?? 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 30 04 1e 43 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_AW_2147820322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AW!MTB"
        threat_id = "2147820322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 34 10 68 [0-4] 68 [0-4] e8 [0-4] 83 c4 ?? 0f af f0 89 b5 [0-4] 8b 4d ?? 03 4d ?? 8a 11 88 55 ?? 0f be 45 ?? 33 85 [0-4] 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_XE_2147820470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.XE!MTB"
        threat_id = "2147820470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 69 72 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 72 6f 74 65 66 c7 05 ?? ?? ?? ?? 63 74 c6 05 ?? ?? ?? ?? 00 ff 15 5c 10 40 00 a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_V_2147820478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.V!MTB"
        threat_id = "2147820478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 69 72 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 72 6f 74 65 66 c7 05 ?? ?? ?? ?? 63 74 c6 05 ?? ?? ?? ?? ?? ff 15 3c 10 40 00}  //weight: 10, accuracy: Low
        $x_10_2 = {50 ff 75 fc ff 35 c4 0a 91 00 ff 35 24 50 ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_XF_2147821053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.XF!MTB"
        threat_id = "2147821053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 44 24 14 8b 44 24 ?? 01 44 24 ?? 8b f7 c1 e6 ?? 03 74 24 ?? 33 74 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 09 55 55 55 ff 15 ?? ?? ?? ?? 33 74 24 ?? 89 2d ?? ?? ?? ?? 89 74 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_XK_2147822325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.XK!MTB"
        threat_id = "2147822325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c8 8b 45 fc 99 33 c1 89 45 fc 8b 55 0c 89 55 08 8b 45 fc 89 45 0c 8b 4d 08 03 4d 0c 89 4d f4 8b 45 f4 8b e5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_XO_2147822905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.XO!MTB"
        threat_id = "2147822905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 89 4d f8 c7 45 ?? ?? ?? ?? ?? ba ?? ?? ?? ?? 66 89 55 ?? 8b 45 ?? 35 ?? ?? ?? ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? 8b 4d ?? 81 c1 ?? ?? ?? ?? 89 4d ?? c7 45 ?? ?? ?? ?? ?? 83 7d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_XH_2147823559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.XH!MTB"
        threat_id = "2147823559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 1d a1 ed eb 01 d3 33 c0 79 ?? ?? 4d 82 71 ?? ?? 04 ?? 33 28 a2 ?? ?? ?? ?? ea}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_XS_2147823622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.XS!MTB"
        threat_id = "2147823622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 da 8b 4d f8 8b 45 0c 01 c8 8b 5d f8 8b 4d 0c 01 d9 0f b6 09 31 ca 88 10 83 45}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyStealer_AZ_2147823637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyStealer.AZ!MTB"
        threat_id = "2147823637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c6 f7 75 10 8a 0c 1a 30 0c 3e 46 3b 75 14 72}  //weight: 1, accuracy: High
        $x_1_2 = "uhUIAHsyutfTWt678" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


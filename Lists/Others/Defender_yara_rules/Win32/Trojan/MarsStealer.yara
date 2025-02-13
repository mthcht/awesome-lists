rule Trojan_Win32_MarsStealer_MB_2147812648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.MB!MTB"
        threat_id = "2147812648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 f9 02 33 c1 0f b7 15 ?? ?? ?? 00 c1 fa 03 33 c2 0f b7 0d ?? ?? ?? 00 c1 f9 05 33 c1 83 e0 01 a3 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d2 b9 24 00 00 00 f7 f1 8b 85 e4 fe ff ff 8a 8a ?? ?? ?? 00 88 8c 05 f8 fe ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MarsStealer_MB_2147812648_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.MB!MTB"
        threat_id = "2147812648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 08 8d 94 11 ?? ?? ?? ?? 8b 45 fc 03 45 e0 88 10 8b 4d fc 03 4d e0 0f b6 11 81 ea 8b 10 00 00 8b 45 fc 03 45 e0 88 10 c7 45 f0 01 00 00 00 8b 4d f8 83 c1 01 89 4d f8 e9}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "Process32FirstW" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_6 = "CreateMutexA" ascii //weight: 1
        $x_1_7 = "SetKeyboardState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MarsStealer_MA_2147816621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.MA!MTB"
        threat_id = "2147816621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8b 4c 24 10 c1 e8 05 03 44 24 28 33 cb c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 18 89 4c 24 10 8b 44 24 18 31 44 24 10 2b 74 24 10 81 c7 ?? ?? ?? ?? 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MarsStealer_MA_2147816621_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.MA!MTB"
        threat_id = "2147816621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 a3 ?? ?? ?? ?? 68 19 00 8b ec 68 ?? ?? ?? ?? e8 [0-21] e8 ?? ?? ?? ?? 83 c4 04 a3 ?? ?? ?? ?? ?? 8b 44 24 04 05 1a 58 01 00 ff d0}  //weight: 10, accuracy: Low
        $x_10_2 = {8b ec c7 05 6c 73 41 00 50 30 41 00 c7 05 f0 71 41 00 68 30 41 00 c7 05 68 74 41 00 78 30 41 00 c7 05 c0 77 41 00 88 30 41 00 c7 05 f8 70 41 00 94 30 41 00 c7 05 48 76 41 00 a4 30 41 00 c7 05 04 77 41 00 b0 30 41 00 c7 05 34 73 41 00 c0 30 41 00 c7 05 ac 75 41 00 c8 30 41 00 c7 05 a4 74 41 00 e0 30 41 00}  //weight: 10, accuracy: High
        $x_1_3 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MarsStealer_MC_2147818451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.MC!MTB"
        threat_id = "2147818451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c7 f3 a4 c6 07 5c 83 c7 01 8d 35 ?? ?? ?? ?? b9 22 00 00 00 f3 a4 83 c7 01 89 3d ?? ?? ?? ?? 59 8d 35 ?? ?? ?? ?? f3 a4 c6 07 5c 83 c7 01 8d 35 ?? ?? ?? ?? b9 0c 00 00 00 f3 a4 e9}  //weight: 5, accuracy: Low
        $x_5_2 = "MarsStealer8_cracked_by_" ascii //weight: 5
        $x_5_3 = "LLCPPC" ascii //weight: 5
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "Code encryption pass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MarsStealer_AMS_2147894232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.AMS!MTB"
        threat_id = "2147894232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 03 4c 24 ?? 8b d0 c1 e2 04 03 54 24 ?? 03 c3 33 ca 33 c8 2b f9 8b cf c1 e1 04}  //weight: 1, accuracy: Low
        $x_1_2 = {52 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b f7 c1 ee 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MarsStealer_RPY_2147895021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.RPY!MTB"
        threat_id = "2147895021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f6 8b cf c1 e1 04 03 4c 24 2c 8b c7 c1 e8 05 03 44 24 3c 8d 14 3b 33 ca 89 44 24 1c 89 4c 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MarsStealer_RPX_2147895660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.RPX!MTB"
        threat_id = "2147895660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 ff 8b d0 c1 ea 05 03 d5 8b c8 c1 e1 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 20 31 44 24 10 8b 44 24 10 29 44 24 1c c7 44 24 18 00 00 00 00 8b 44 24 34 01 44 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MarsStealer_RDA_2147899253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.RDA!MTB"
        threat_id = "2147899253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 e0 0f b6 14 37 c1 e2 08 8b 0c b0 46 0f b6 01 32 9c 10 00 7a 42 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MarsStealer_RDB_2147909509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsStealer.RDB!MTB"
        threat_id = "2147909509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 ec 89 45 f0 8b 4d e4 8b c7 d3 e8 89 45 f8 8b 45 dc 01 45 f8 8b 45 f8 33 45 f0 31 45 fc 8b 45 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


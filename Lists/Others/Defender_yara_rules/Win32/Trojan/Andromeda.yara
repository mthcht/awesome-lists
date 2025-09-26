rule Trojan_Win32_Andromeda_RPZ_2147846546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Andromeda.RPZ!MTB"
        threat_id = "2147846546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f8 8b 51 54 52 8b 45 08 8b 48 0c 51 8b 55 d0 52 8b 45 d8 50 8b 4d 08 8b 91 80 00 00 00 ff d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Andromeda_RPZ_2147846546_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Andromeda.RPZ!MTB"
        threat_id = "2147846546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Andromeda_RPZ_2147846546_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Andromeda.RPZ!MTB"
        threat_id = "2147846546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 14 56 57 8b 7d 08 33 f6 89 47 0c 39 75 10 76 15 8b 45 0c 57 8d 14 06 e8 ?? ?? ?? ?? 30 02 46 59 3b 75 10 72 eb 5f 5e 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Andromeda_RPW_2147850592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Andromeda.RPW!MTB"
        threat_id = "2147850592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 e0 fe ff ff 4d c6 85 e1 fe ff ff 65 c6 85 e2 fe ff ff 73 c6 85 e3 fe ff ff 73 c6 85 e4 fe ff ff 61 c6 85 e5 fe ff ff 67 c6 85 e6 fe ff ff 65 c6 85 e7 fe ff ff 42 c6 85 e8 fe ff ff 6f c6 85 e9 fe ff ff 78 c6 85 ea fe ff ff 41 c6 85 eb fe ff ff 00 8d 95 d8 fe ff ff 52 ff 95 20 ff ff ff 89 85 30 ff ff ff 8d 85 e0 fe ff ff 50 8b 8d 30 ff ff ff 51 ff 95 24 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Andromeda_RPY_2147899143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Andromeda.RPY!MTB"
        threat_id = "2147899143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 85 54 ff ff ff c6 85 5c fe ff ff 56 c6 85 5d fe ff ff 69 c6 85 5e fe ff ff 72 c6 85 5f fe ff ff 74 c6 85 60 fe ff ff 75 c6 85 61 fe ff ff 61 c6 85 62 fe ff ff 6c c6 85 63 fe ff ff 41 c6 85 64 fe ff ff 6c c6 85 65 fe ff ff 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Andromeda_AHB_2147953208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Andromeda.AHB!MTB"
        threat_id = "2147953208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Andromeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b cf 2b f7 8a 04 0e 8d 49 01 88 41 ff 42 8b 44 24 0c 3b d0 72}  //weight: 20, accuracy: High
        $x_30_2 = {8b c1 c1 e8 ?? 30 04 3a 42 3b 54 24 0c 7c ?? 89 0d ?? ?? ?? ?? 8b cf}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


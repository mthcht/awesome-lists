rule Trojan_Win32_FatalRAT_B_2147898608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRAT.B!MTB"
        threat_id = "2147898608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c2 30 54 3e ?? 46 3b b5 1b 00 8a 44 3e ?? 32 85 ?? ?? ff ff 88 44 3e ?? e8 ?? ?? ?? ?? 99 f7 bd ?? ?? ff ff fe}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 04 3e 32 85 ?? ?? ff ff 88 04 3e e8 ?? ?? ?? ?? 99 f7 bd ?? ?? ff ff fe c2 30 14 3e 46 3b b5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FatalRAT_EC_2147903130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRAT.EC!MTB"
        threat_id = "2147903130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyboardManager" ascii //weight: 1
        $x_1_2 = "DockingManagers" ascii //weight: 1
        $x_1_3 = "RestartByRestartManager:" ascii //weight: 1
        $x_1_4 = "ShellCodeLoader.pdb" ascii //weight: 1
        $x_1_5 = "WINDOWS\\system32\\1.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FatalRAT_C_2147920254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRAT.C!MTB"
        threat_id = "2147920254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 50 ff ?? ?? 14 54 00 8b f0 83 fe ff 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 08 8b f0 6a 0a 8b ce e8 ?? ?? 00 00 8b 06 8b 40 04 eb ?? 8b 03 8b 4b 04 6a 00 8d 55 fc 52 2b c8 51 50 56 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FatalRAT_D_2147920795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRAT.D!MTB"
        threat_id = "2147920795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 85 c0 ?? ?? 8d 34 ?? ?? ?? ?? ?? 66 8b 3e 66 3b 3c 53 ?? ?? 42 83 c6 02 3b d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FatalRAT_GTT_2147931019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRAT.GTT!MTB"
        threat_id = "2147931019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 e4 ?? 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 8d 44 24 ?? 33 f6 50 6a 40 56 56 89 74 24 ?? ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


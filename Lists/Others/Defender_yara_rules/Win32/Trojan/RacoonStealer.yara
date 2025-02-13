rule Trojan_Win32_RacoonStealer_AZ_2147793427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RacoonStealer.AZ!MTB"
        threat_id = "2147793427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RacoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 08 89 38 5f 5e 89 50 04 5b c9 c2 04 00 28 00 2b 7d ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
        $x_1_2 = "LocalAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RacoonStealer_AY_2147794055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RacoonStealer.AY!MTB"
        threat_id = "2147794055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RacoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 08 5f 89 30 5e 89 58 04 5b c9 c2 04 00 2b 00 2b 75 ?? 8d 45 ?? 89 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
        $x_1_2 = "LocalAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RacoonStealer_RT_2147796504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RacoonStealer.RT!MTB"
        threat_id = "2147796504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RacoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OXDK/F\\pGF\\[@]VpJANM ENCRYPTEDpASSWOpPP]P" ascii //weight: 1
        $x_1_2 = "CryptDestroyHash" ascii //weight: 1
        $x_1_3 = "Login Data" ascii //weight: 1
        $x_1_4 = "Cookies" ascii //weight: 1
        $x_1_5 = "HTTP Password" ascii //weight: 1
        $x_1_6 = "SMTP Password" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Internet Account Manager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RacoonStealer_RPC_2147798308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RacoonStealer.RPC!MTB"
        threat_id = "2147798308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RacoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RacoonStealer_RPD_2147798309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RacoonStealer.RPD!MTB"
        threat_id = "2147798309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RacoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 84 24 34 08 00 00 8b 4c 24 18 8b 54 24 14 5e 5d 89 08 89 50 04 5b 81 c4 24 08 00 00 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


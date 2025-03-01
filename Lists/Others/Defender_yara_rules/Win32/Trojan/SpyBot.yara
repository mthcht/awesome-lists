rule Trojan_Win32_Spybot_RSB_2147771441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spybot.RSB!MTB"
        threat_id = "2147771441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spybot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 d7 fe c0 34 5b 04 4f 34 de fe c0 2c 7d 04 cf fe c8 34 f1 04 02 fe c0 fe c0 fe c0 fe c8 34 b7 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spybot_RSB_2147771441_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spybot.RSB!MTB"
        threat_id = "2147771441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spybot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 eb 6f 00 8a 84 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 74 [0-15] 34 [0-15] 34 [0-15] 34 [0-15] 34 [0-15] 34 [0-31] 88 84 0d 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spybot_RSB_2147771441_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spybot.RSB!MTB"
        threat_id = "2147771441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spybot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 83 c1 01 eb ?? b0 00 b9 00 00 00 00 8d 45 f8 50 6a 40 2f 00 34 ?? ?? ?? ?? ?? 2c [0-10] 88 84 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 39 88 07 8d 7f 01 4e 75 1f 00 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spybot_RPB_2147824988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spybot.RPB!MTB"
        threat_id = "2147824988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spybot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 0c 24 c1 24 24 04 8b 44 24 0c 01 04 24 89 4c 24 04 c1 6c 24 04 05 8b 44 24 14 01 44 24 04 03 4c 24 10 89 4c 24 10 8b 44 24 10 31 04 24 8b 44 24 04 33 04 24 83 c4 08 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


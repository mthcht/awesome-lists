rule Trojan_Win32_Spy_BYF_2147782382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spy.BYF!MTB"
        threat_id = "2147782382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Stealing Browsers" ascii //weight: 2
        $x_2_2 = "Invoke StealerPlugin" ascii //weight: 2
        $x_1_3 = "Grabbing discord tokens" ascii //weight: 1
        $x_1_4 = "Grabbing passwords" ascii //weight: 1
        $x_1_5 = "Passman Data" ascii //weight: 1
        $x_1_6 = "Credit Cards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spy_Zbot_2147794451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spy.Zbot.ACM!MTB"
        threat_id = "2147794451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spy"
        severity = "Critical"
        info = "ACM: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 f8 8a 02 88 45 fc 8b 4d 0c 03 4d ec 33 d2 8a 11 8b 45 fc 25 ff 00 00 00 33 d0 8b 4d 0c 03 4d ec 88 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spy_RPM_2147797355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spy.RPM!MTB"
        threat_id = "2147797355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 14 8b f2 8b c8 2b f0 8b d7 8a 1c 0e 32 5d 0c 88 19 41 4a 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spy_Casbaneiro_2147946058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spy.Casbaneiro.GA!MTB"
        threat_id = "2147946058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spy"
        severity = "Critical"
        info = "GA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 83 e8 02 74 21 2d 10 01 00 00 75 23 8b 45 14 50 8b 45 10 50 8b 45 0c 50 8b 45 08 50 ?? ?? ?? ?? ?? 89 45 fc eb 28 6a 00 ?? ?? ?? ?? ?? eb 1a 8b 45 14 50 8b 45 10 50 8b 45 0c 50 8b 45 08 50 ?? ?? ?? ?? ?? 89 45 fc eb 05 33 c0 89 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spy_NF_2147952539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spy.NF!MTB"
        threat_id = "2147952539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 b0 8b 14 95 88 20 43 00 03 d1 8a 0c 03 03 d3 43 88 4c 32 2e 8b 4d bc 3b df 7c e3}  //weight: 2, accuracy: High
        $x_1_2 = {8b 45 b4 8a 0a 88 4c 07 2e 8b 45 b0 8b 04 85 88 20 43 00 80 4c 38 2d 04 8b 45 b8 40 89 46 04 eb 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


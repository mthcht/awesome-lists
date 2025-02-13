rule Trojan_Win32_MiniDuke_A_2147752035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MiniDuke.A!dha"
        threat_id = "2147752035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniDuke"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "proc:  %d %s" ascii //weight: 10
        $x_10_2 = "login: %s\\%s" ascii //weight: 10
        $x_10_3 = "ID:    0x%08X" ascii //weight: 10
        $x_10_4 = "host:  %s:%d" ascii //weight: 10
        $x_10_5 = "meth:  %s %d" ascii //weight: 10
        $x_10_6 = "pipe: \\\\%s\\pipe\\%s" ascii //weight: 10
        $x_10_7 = "lang:  %s" ascii //weight: 10
        $x_10_8 = "delay: %d" ascii //weight: 10
        $x_30_9 = "ecolesndmessines.org" ascii //weight: 30
        $x_30_10 = "salesappliances.com" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MiniDuke_BS_2147831450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MiniDuke.BS!MTB"
        threat_id = "2147831450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniDuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 84 24 bc 00 00 00 30 02 89 f8 42 03 84 24 bd 00 00 00 39 c2 eb}  //weight: 5, accuracy: High
        $x_5_2 = {0f b6 02 42 34 b9 88 01 41 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MiniDuke_RB_2147833853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MiniDuke.RB!MTB"
        threat_id = "2147833853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniDuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 4d fe c1 e0 0d 33 c1 33 05 ?? ?? ?? ?? 69 c0 0d 66 19 00 05 6c 59 88 3c 33 d2 f7 75 0c 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MiniDuke_RF_2147840780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MiniDuke.RF!MTB"
        threat_id = "2147840780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniDuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e0 3f 83 c0 20 8b 8d f0 d3 ff ff 88 01 8b 85 90 e7 ff ff 0f be 00 25 c0 00 00 00 8b 8d f4 d3 ff ff d3 f8 0f b6 8d 9f e7 ff ff 0b c8 88 8d 9f e7 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MiniDuke_SG_2147908720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MiniDuke.SG!MTB"
        threat_id = "2147908720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniDuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0d 18 30 40 00 09 c9 74 11 a1 10 30 40 00 8d 0c 88 51 50 e8 b5 ff ff ff 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


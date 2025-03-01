rule Trojan_Win32_Spysnake_MX_2147840906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spysnake.MX!MTB"
        threat_id = "2147840906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spysnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c8 f7 e3 d1 ea 83 e2 fc 8d 04 52 f7 d8 8a 04 07 8b 54 24 20 30 04 0a 41 47 39 ce 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spysnake_MY_2147840987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spysnake.MY!MTB"
        threat_id = "2147840987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spysnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c4 10 33 c9 39 5d 10 76 17 8b c1 99 6a 0c 5f f7 ff 8a 82 38 e7 40 00 30 04 0e 41 3b 4d 10 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spysnake_MZ_2147841616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spysnake.MZ!MTB"
        threat_id = "2147841616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spysnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a 90 08 92 40 00 30 14 31 41 3b cf 72 dd}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spysnake_MAA_2147841643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spysnake.MAA!MTB"
        threat_id = "2147841643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spysnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c4 10 33 c9 5b 85 ff 74 23 b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a 90 f0 91 40 00 30 14 31 41 3b cf 72 dd}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spysnake_MAB_2147842411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spysnake.MAB!MTB"
        threat_id = "2147842411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spysnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f4 03 55 fc 0f b6 02 33 c1 8b 4d f4 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc eb c8 8d 45 e8 50 6a 40 8b 4d f8 51 8b 55 f4 52 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


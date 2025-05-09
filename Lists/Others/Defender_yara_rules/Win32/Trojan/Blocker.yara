rule Trojan_Win32_Blocker_PE_2147795328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blocker.PE!MTB"
        threat_id = "2147795328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "53aa3a5a831d66bae5b39fdef87e9243edcd6d5fb50d84a70b6f403ef9c5ade1" wide //weight: 1
        $x_1_2 = "VOtVPw38.exe" wide //weight: 1
        $x_1_3 = "XIPiQMZn.exe" wide //weight: 1
        $x_1_4 = "MxbyKWKP.exe" wide //weight: 1
        $x_1_5 = "w2QtYwVF.exe" wide //weight: 1
        $x_1_6 = "A8LQM6Zg.exe" wide //weight: 1
        $x_1_7 = "4fg5Mzmp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blocker_BD_2147835736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blocker.BD!MTB"
        threat_id = "2147835736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 1c 18 01 1b 35 00 05 36 00 24 37 00 0f fc 02 19 68 ff 08 68 ff 0d b4 00 38 00 1a 68 ff 80 10 00 1b 1c 00 2a 23}  //weight: 2, accuracy: High
        $x_2_2 = {1b 29 00 2a 23 2c ff 1b 26 00 2a 46 14 ff 0a 2a 00 08 00 74 0c ff 32 18 00 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blocker_BE_2147836034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blocker.BE!MTB"
        threat_id = "2147836034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 46 69 6c 65 31 00 00 00 2e 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 3a 5c 50 72 6f 67 72}  //weight: 2, accuracy: High
        $x_2_2 = {35 34 ff 00 10 6c 10 00 04 34 ff 0a 1a 00 08 00 35 34 ff 00 00 fd 95}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blocker_BF_2147836998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blocker.BF!MTB"
        threat_id = "2147836998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c3 2b c2 66 03 c8 8b 84 2f 97 fc ff ff 05 04 5c 01 01 89 84 2f 97 fc ff ff 8b f2 2b f3 8b eb c1 e5 04 83 ee 03 03 eb 89 35 [0-4] 2b f5 8b 6c 24 14 83 c5 04 81 fd 59 04 00 00 66 89 0d [0-4] a3 [0-4] 89 6c 24 14 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blocker_DAT_2147851787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blocker.DAT!MTB"
        threat_id = "2147851787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {05 00 6c 70 ff fb 3d 2f 70 ff 1c 4e 04 f4 00 1c 24 04 fc c8 f4 00 1c 2b 04 fc c8 f4 00 1c 32 04 fc c8 f4 00 1c 39 04 fc c8 f5 02 00 00 00 6c 78}  //weight: 2, accuracy: High
        $x_2_2 = {35 3c ff 1c 6a 05 f4 00 1c 16 05 fc c8 f4 00 1c 1d 05 fc c8 f4 00 1c 24 05 fc c8 f4 00 1c 2b 05 fc c8 f5 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blocker_NB_2147933402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blocker.NB!MTB"
        threat_id = "2147933402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 05 8b 45 ec eb 3a 8b 0d ?? ?? ?? ?? 81 e1 00 80 00 00 85 c9 74 09 c7 45 e4 ?? ?? ?? ?? eb 07 c7 45 e4 cc 3d 43 00}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 4d 0c 8b 14 81 52 e8 b2 50 00 00 83 c4 08 85 c0 74 6d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blocker_NIT_2147941022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blocker.NIT!MTB"
        threat_id = "2147941022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 bd 80 fe ff ff ff 15 20 e0 40 00 8b f0 56 57 ff 15 38 e0 40 00 56 ff b5 80 fe ff ff 8b f8 ff 15 3c e0 40 00 57 89 85 80 fe ff ff ff 15 14 e0 40 00 8b bd 80 fe ff ff 8b f0 57 e8 07 23 00 00 83 c4 04 89 85 7c fe ff ff 85 ff 74 14 8b c8 2b f0 8b d7 8a 04 0e 8d 49 01 88 41 ff 83 ea 01 75 f2 66 a1 90 2b 41 00 0f 10 05 78 2b 41 00 66 89 85 e8 fe ff ff 8d 85 f8 fe ff ff 68 00 01 00 00 0f 11 85 d0 fe ff ff 50 f3 0f 7e 05 88 2b 41 00 68 94 2b 41 00}  //weight: 2, accuracy: High
        $x_1_2 = {8b ca 83 e1 03 68 08 2b 41 00 f3 a4 68 01 00 00 80 ff 15 04 e0 40 00 85 c0 75 49 8d 8d f8 fe ff ff 8d 51 02 0f 1f 44 00 00 66 8b 01 83 c1 02 66 85 c0 75 f5 2b ca d1 f9 8d 04 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


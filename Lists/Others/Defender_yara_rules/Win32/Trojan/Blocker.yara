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


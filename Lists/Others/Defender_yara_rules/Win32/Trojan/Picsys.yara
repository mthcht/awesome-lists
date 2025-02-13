rule Trojan_Win32_Picsys_PR_2147745582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picsys.PR!MTB"
        threat_id = "2147745582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picsys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "password stealer.exe" ascii //weight: 1
        $x_1_2 = "Kama Sutra Tetris.exe" ascii //weight: 1
        $x_1_3 = "XXX Porn Passwords.exe" ascii //weight: 1
        $x_1_4 = "cute girl giving head.exe" ascii //weight: 1
        $x_1_5 = "Counter Strike CD Keygen.exe" ascii //weight: 1
        $x_1_6 = "play station emulator crack.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Picsys_SRPP_2147836548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picsys.SRPP!MTB"
        threat_id = "2147836548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picsys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d f4 03 4d f8 8a 11 88 55 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 4d ff 81 f1 b7 00 00 00 88 4d ff 0f b6 55 ff c1 fa 02 0f b6 45 ff c1 e0 06 0b d0 88 55 ff 0f b6 4d ff f7 d1 88 4d ff 0f b6 55 ff 81 ea b1 00 00 00 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 81 c2 b5 00 00 00 88 55 ff 0f b6 45 ff 35 e0 00 00 00 88 45 ff 0f b6 4d ff f7 d1 88 4d ff 0f b6 55 ff 81 f2 b0 00 00 00 88 55 ff 0f b6 45 ff 03 45 f8 88}  //weight: 10, accuracy: High
        $x_10_2 = {45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 83 ea 4a 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff 03 4d f8 88 4d ff 0f b6 55 ff 81 f2 f9 00 00 00 88 55 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 4d ff f7 d9 88 4d ff 0f b6 55 ff 2b 55 f8 88 55 ff 0f b6 45 ff d1 f8 0f b6 4d ff c1 e1 07 0b c1 88 45 ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff c1 f9 05 0f b6 55 ff c1 e2 03 0b ca 88 4d ff 0f b6 45 ff 2b 45 f8 88 45 ff 8b 4d f4 03 4d f8 8a 55 ff 88 11 e9 b1 fe ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Picsys_GMC_2147853351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picsys.GMC!MTB"
        threat_id = "2147853351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picsys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {1b 06 00 01 b4 27 20 24 9a 26 0e 63 09 30 1e 22 a3 3c e0 1b d2 45 30 08 0c 70 5e 59}  //weight: 10, accuracy: High
        $x_1_2 = ".imports" ascii //weight: 1
        $x_1_3 = "@.themida" ascii //weight: 1
        $x_1_4 = "TJprojMain.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Picsys_GMA_2147900367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picsys.GMA!MTB"
        threat_id = "2147900367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picsys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 80 34 01 c0 4e 47 4e 0e ba ?? ?? ?? ?? e2}  //weight: 10, accuracy: Low
        $x_1_2 = "TJprojMain" ascii //weight: 1
        $x_1_3 = "@.themida" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


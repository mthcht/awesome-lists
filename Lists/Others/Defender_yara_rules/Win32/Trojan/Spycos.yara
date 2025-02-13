rule Trojan_Win32_Spycos_B_2147655457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spycos.B"
        threat_id = "2147655457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cjKFSHMI2Ez1yVr3AJRpSaS4KXxgSYULtQOW1zZWLN" ascii //weight: 1
        $x_1_2 = {8d 55 f8 b8 7b 00 00 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spycos_C_2147655458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spycos.C"
        threat_id = "2147655458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 8d 95 90 fa ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 90 fa ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 e8 6a 04 68 ?? ?? ?? ?? 6a 02 8b 45 e8 50 e8 ?? ?? ?? ?? 6a 04 68 ?? ?? ?? ?? 6a 06 8b 45 e8 50 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ?? 50 8b 45 e8 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 89 45 f8 8b c3 2c 04 74 0f b6 c3 50 8b c7 5a 8b ca 99 f7 f9 85 d2 75 0f b6 c3 8b d7 2b d0 8b 45 fc 8b 44 90 08 33 45 f8 89 46 04 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spycos_D_2147655770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spycos.D"
        threat_id = "2147655770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 55 cc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 cc 8b 55 f8 e8 ?? ?? ?? ?? 85 c0 8b 45 fc e8 ?? ?? ?? ?? 8b d8}  //weight: 1, accuracy: Low
        $x_1_2 = {76 4a 8d 45 9c 50 6a (3c|64) 6a 0d 53 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "modguard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spycos_E_2147667646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spycos.E"
        threat_id = "2147667646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\modguard.pas" ascii //weight: 1
        $x_1_2 = {8b 00 8b 10 ff 52 38 eb 05 e8 ?? ?? ?? ?? 5b e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f4 89 45 f0 8b 5d f0 85 db 74 05 83 eb 04 8b 1b 43 53 8d 55 ec a1}  //weight: 1, accuracy: High
        $x_1_4 = {75 34 8d 55 ?? b8 ?? ?? 41 00 e8 ?? ?? ff ff 8b 45 ?? 50 8d 55 ?? b8 ?? ?? 41 00 e8 ?? ?? ff ff 8b 45 ?? 8d 4d ?? 5a e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Spycos_H_2147682666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spycos.H"
        threat_id = "2147682666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spycos_H_2147682666_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spycos.H"
        threat_id = "2147682666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 e4 3b 7d ec 7d 03 47 eb 05 bf 01 00 00 00 8b 45 f4 0f b6 5c 38 ff 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 eb 03 2b 5d e8 8d 45 d0 8b d3 e8 ?? ?? ?? ff 8b 55 d0 8d 45 f8 e8 ?? ?? ?? ff 8b 45 e4 89 45 e8 83 c6 02 8b 45 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {00 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6d 6d 79 79 79 79 00 00 ff ff ff ff 04 00 00 00 2e 73 71 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spycos_I_2147683934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spycos.I"
        threat_id = "2147683934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ControlPanelCpl.cpl" ascii //weight: 4
        $x_4_2 = "UPD 10 DISCARDABLE \"htmlgrd.exe\"" ascii //weight: 4
        $x_1_3 = "[ INFECT VIA TXT" ascii //weight: 1
        $x_1_4 = "Plugin RED......" ascii //weight: 1
        $x_1_5 = "Plugin GB......." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


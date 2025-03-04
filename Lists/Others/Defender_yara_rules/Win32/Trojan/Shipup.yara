rule Trojan_Win32_Shipup_B_2147600994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shipup.B"
        threat_id = "2147600994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shipup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 04 8a 08 84 c9 74 08 80 c1 03 88 08 40 eb f2 c3 8b 44 24 04 8a 08 84 c9 74 07 fe c1 88 08 40 eb f3 c3}  //weight: 10, accuracy: High
        $x_5_2 = "MicrosoftFlash" ascii //weight: 5
        $x_1_3 = "\\ld.exe" ascii //weight: 1
        $x_1_4 = "\\filetime.dat" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\ShipTr" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Shipup_C_2147610117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shipup.C"
        threat_id = "2147610117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shipup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 04 8a 08 84 c9 74 08 80 e9 02 88 08 40 eb}  //weight: 10, accuracy: High
        $x_1_2 = "autorun.inf" ascii //weight: 1
        $x_1_3 = "MicrosoftShip" ascii //weight: 1
        $x_1_4 = "NoDriveTypeAutoRun" ascii //weight: 1
        $x_1_5 = "Maybe a Encrypted Flash Disk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Shipup_D_2147611292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shipup.D"
        threat_id = "2147611292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shipup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {7e 21 53 8b 44 24 08 8d 0c 02 8a 04 02 2a c2 8a d8 c0 eb 04 c0 e0 04 02 d8 42 3b 54 24 0c 88 19 7c e1}  //weight: 7, accuracy: High
        $x_5_2 = {3b c3 75 27 8a 85 78 ff ff ff 3a c3 74 12 fe c8 88 86 ?? ?? 40 00 8a 84 35 79 ff ff ff 46 eb ea 39 5d 08 88 9e ?? ?? 40 00 74 77 57 8d 85 78 fd ff ff 68 00 02 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = "MicrosoftFlash" ascii //weight: 1
        $x_1_4 = "\\filetime.dat" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\ShipTr" ascii //weight: 1
        $x_1_6 = "Maybe a Encrypted Flash Disk" ascii //weight: 1
        $x_1_7 = "UnHook OK!" ascii //weight: 1
        $x_1_8 = "MicrosoftShipHaveAck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 6 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Shipup_J_2147656730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shipup.J"
        threat_id = "2147656730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shipup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "XP-Update" ascii //weight: 1
        $x_1_2 = "-mouse.log" ascii //weight: 1
        $x_1_3 = {6d 73 64 6e 00 00 00 00 5c 2a 2e 2a}  //weight: 1, accuracy: High
        $x_1_4 = {8b 44 24 04 03 c1 8a 10 2a d1 80 f2 ?? 80 ea ?? 41 3b 4c 24 08 88 10 7c e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shipup_GJU_2147850648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shipup.GJU!MTB"
        threat_id = "2147850648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shipup"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 e4 89 45 fc 8b 4d d0 89 4d f0 8b 55 cc 89 55 f8 8b 45 cc 89 45 e0 8b 4d e0 8b 11 33 55 f0 8b 45 e0 89 10}  //weight: 10, accuracy: High
        $x_10_2 = {00 c7 45 c8 35 dc 07 00 8b 55 ec 89 55}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shipup_AMAB_2147852134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shipup.AMAB!MTB"
        threat_id = "2147852134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shipup"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 dc 89 f3 89 ca e8 ?? ?? ?? ?? 89 45 e8 89 f3 89 ca 8b 45 dc e8 ?? ?? ?? ?? 8b 55 e4 23 45 f4 01 c2 8b 45 e8 33 45 dc 8b 5d dc 03 45 e4 ff 45 fc e8 ?? ?? ?? ?? 81 7d fc e8 07 00 00 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 00 8d 7b 01 99 f7 ff 88 45 fc 8a 06 0c 01 0f b6 f8 89 d8 99 f7 ff 0f b6 3e 01 f8 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shipup_AMAB_2147852134_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shipup.AMAB!MTB"
        threat_id = "2147852134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shipup"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e8 01 c2 8b 45 f0 03 45 e0 89 45 ec 8b 45 e8 03 45 ec 41 e8 ?? ?? ?? ?? 81 f9 e8 07 00 00 7d ?? 8b 45 e0 89 f3 89 fa e8 ?? ?? ?? ?? 89 45 f0 89 f3 89 fa 8b 45 e0 e8 ?? ?? ?? ?? 8b 5d e0 85 db 74}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c6 89 d7 88 d9 0f b6 00 d3 f8 89 c1 0f b6 02 8d 53 01 89 55 fc 99 f7 7d fc 88 06 88 c8 0c 01 0f b6 f0 89 d8 99 f7 fe 0f b6 c9 01 c8 88 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shipup_GPA_2147892038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shipup.GPA!MTB"
        threat_id = "2147892038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shipup"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ba 7a dc 1e 86 1d 2e 60 ce e0 02 01 33 73 49 83 72 70 61 0e 71 67 92 b2 80 f5 32 fe ab 62 bf 76 d9 e4 13 ab 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


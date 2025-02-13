rule Trojan_Win32_Opalcot_A_2147575008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Opalcot.A"
        threat_id = "2147575008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Opalcot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 05 80 38 b8 74 03 33 c0 c3 8b 40 01 8b 4c 24 08 89 01 33 c0 40}  //weight: 2, accuracy: High
        $x_2_2 = {c7 06 5c 11 00 00 83 c7 1e 83 c6 04 ff 4d fc 75 e2 bf 00 90 01 00 57 6a 40}  //weight: 2, accuracy: High
        $x_2_3 = {8b 45 fc 0f b7 00 8b d8 66 81 e3 00 f0 66 81 fb 00 30}  //weight: 2, accuracy: High
        $x_2_4 = {66 81 38 4d 5a 75 3c 8b 48 3c 03 c1 b9 50 45 00 00 39 08 75 2e 8b 54 24 08 89 02 39 08}  //weight: 2, accuracy: High
        $x_1_5 = {6a 08 8d 45 f4 50 68 10 09 32 38}  //weight: 1, accuracy: High
        $x_1_6 = {40 00 10 33 c9 8a 08 83 f1}  //weight: 1, accuracy: High
        $x_1_7 = "__ANTIVIR__" ascii //weight: 1
        $x_1_8 = {53 00 4f 00 55 00 4e 00 44 00 4d 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_10 = "SystemRoot\\system32\\drivers" ascii //weight: 1
        $x_1_11 = "kav.dll" ascii //weight: 1
        $x_1_12 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Opalcot_2147575009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Opalcot!sys"
        threat_id = "2147575009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Opalcot"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c c7 40 18 0d 00 00 c0 8b 4d 0c 8b 51 18 89 55 e4 32 d2}  //weight: 1, accuracy: High
        $x_1_2 = {8d 45 fc 50 6a 00 6a 00 68 32 38 59 00 8d 4d f4 51 6a 00 8b 55 08 52}  //weight: 1, accuracy: High
        $x_2_3 = {50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 a1}  //weight: 2, accuracy: High
        $x_2_4 = {89 45 fc 50 0f 20 c0 0d 00 00 01 00 0f 22 c0 58 8b 45 fc}  //weight: 2, accuracy: High
        $x_2_5 = "KeServiceDescriptorTable" ascii //weight: 2
        $x_1_6 = {01 00 00 75 0a b8 01 00 00 c0 e9}  //weight: 1, accuracy: High
        $x_1_7 = "Device\\KWatch" ascii //weight: 1
        $x_1_8 = {8b 45 f8 8b 48 0c 89 4d ec 8b 55 ec 89 55 d4 81 7d d4 10 09 32 38 74 02}  //weight: 1, accuracy: High
        $x_1_9 = {83 7d fc 08 72 21 8b 45 f4 8b 48 04 51 8b 55 f4 8b 02 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


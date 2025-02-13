rule Trojan_Win32_Necurs_A_162154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Necurs.A"
        threat_id = "162154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Necurs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\NtSecureSys" wide //weight: 1
        $x_1_2 = {8d 14 90 03 d2 c1 ce 0d 33 f2 03 c6 88 19 41 ff 4d 0c 75 e1}  //weight: 1, accuracy: High
        $x_1_3 = {35 de c0 ad de 89 45 ?? ff 15 ?? ?? ?? ?? 33 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Necurs_A_179055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Necurs.gen!A"
        threat_id = "179055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Necurs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 3f 00 3f 00 5c 00 4e 00 74 00 53 00 65 00 63 00 75 00 72 00 65 00 53 00 79 00 73 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {5c 5c 2e 5c 4e 74 53 65 63 75 72 65 53 79 73 00}  //weight: 10, accuracy: High
        $x_10_3 = {44 00 42 00 35 00 00 00 44 00 42 00 36 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {44 00 42 00 31 00 00 00 6c 73 61 73 73 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_5 = {62 63 64 65 64 69 74 2e 65 78 65 20 2d 73 65 74 20 54 45 53 54 53 49 47 4e 49 4e 47 20 4f 4e 00}  //weight: 1, accuracy: High
        $x_1_6 = {32 00 30 00 31 00 30 00 31 00 00 00 00 00 00 00 4f 00 62 00 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 43 00 61 00 6c 00 6c 00 62 00 61 00 63 00 6b 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 00 6f 00 6f 00 74 00 20 00 42 00 75 00 73 00 20 00 45 00 78 00 74 00 65 00 6e 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {4b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Necurs_A_179055_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Necurs.gen!A"
        threat_id = "179055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Necurs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 fc fc ff ff 72 c6 85 fd fc ff ff 77 c6 85 fe fc ff ff 63 c6 85 ff fc ff ff 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff d2 33 c0 b0 04 03 e0}  //weight: 1, accuracy: High
        $x_1_3 = {3d 35 8e f8 1f 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Necurs_A_179055_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Necurs.gen!A"
        threat_id = "179055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Necurs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4b 3c 03 cb 8b 81 a0 00 00 00 8b 91 a4 00 00 00 89 55 f8 85 c0 74 63}  //weight: 1, accuracy: High
        $x_1_2 = {8b 41 3c 6a 00 ff 74 08 50 51 e8 02 ff ff ff 83 c4 0c 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {35 de c0 ad de 89 45 ?? ff 15 ?? ?? ?? ?? 33 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Necurs_A_204014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Necurs.A!!Necurs.gen!A"
        threat_id = "204014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Necurs"
        severity = "Critical"
        info = "Necurs: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4b 3c 03 cb 8b 81 a0 00 00 00 8b 91 a4 00 00 00 89 55 f8 85 c0 74 63}  //weight: 1, accuracy: High
        $x_1_2 = {8b 41 3c 6a 00 ff 74 08 50 51 e8 02 ff ff ff 83 c4 0c 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {35 de c0 ad de 89 45 ?? ff 15 ?? ?? ?? ?? 33 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Necurs_H_235940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Necurs.H"
        threat_id = "235940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Necurs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {35 de c0 ad de 89 45 ?? ff 15 ?? ?? ?? ?? 33 45}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 45 08 0b 45 0c 0f 31 74 ?? 89 45 ?? 35 ?? ?? ?? ?? c1 c0 0b 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {51 83 c0 30 35 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 f4 89 55 f8 eb 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 43 28 03 45 ?? 33 c9 41 89 4d ?? ff 75 18 51 ff 75 ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6a 69 6e c7 45 ?? 6a 70 74 77}  //weight: 1, accuracy: Low
        $x_1_6 = {63 78 63 63 c7 45 ?? 74 76 62 7a}  //weight: 1, accuracy: Low
        $x_1_7 = {78 78 78 70 c7 45 ?? 72 6f 62 69}  //weight: 1, accuracy: Low
        $x_2_8 = {83 f8 04 76 ?? 66 83 bc ?? ?? ff ff ff 74 75 ?? 66 83 bc ?? ?? ff ff ff 69 75 ?? 66 83 bc ?? ?? ff ff ff 62 75 ?? 66 83 bc ?? ?? ff ff ff 2e}  //weight: 2, accuracy: Low
        $x_1_9 = {69 c0 e8 03 00 00 83 c4 10 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff d3}  //weight: 1, accuracy: Low
        $x_1_10 = ".\\NtSecureSys" ascii //weight: 1
        $x_1_11 = ".\\PCI#VEN_25AF&DEV_0209&SUBSYS_070455AF&REV_00" ascii //weight: 1
        $x_1_12 = "-set TESTSIGNING ON" ascii //weight: 1
        $x_1_13 = "/C del /Q /F \"%s\"" ascii //weight: 1
        $x_1_14 = "advfirewall firewall set rule name=\"%s\" dir=%s" ascii //weight: 1
        $x_1_15 = "firewall set opmode mode=DISABLE profile=ALL" ascii //weight: 1
        $x_1_16 = "%s\\drivers\\%s.sys" ascii //weight: 1
        $x_1_17 = {00 66 69 6e 64 6d 65}  //weight: 1, accuracy: High
        $x_1_18 = {00 65 69 6e 69 74}  //weight: 1, accuracy: High
        $x_1_19 = {00 64 65 6c 6d 65}  //weight: 1, accuracy: High
        $x_1_20 = "%s%08x-%04x-%04x-%04x-%08x%04x.tmp" ascii //weight: 1
        $x_1_21 = "%s%0.8X-%0.4X-%0.4X-%0.4X-%0.8X%0.4X}\\" ascii //weight: 1
        $x_1_22 = "%08x %swhen %s at %p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Necurs_H_235941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Necurs.H!!Necurs.gen!B"
        threat_id = "235941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Necurs"
        severity = "Critical"
        info = "Necurs: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {35 de c0 ad de 89 45 ?? ff 15 ?? ?? ?? ?? 33 45}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 45 08 0b 45 0c 0f 31 74 ?? 89 45 ?? 35 ?? ?? ?? ?? c1 c0 0b 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {51 83 c0 30 35 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 f4 89 55 f8 eb 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 43 28 03 45 ?? 33 c9 41 89 4d ?? ff 75 18 51 ff 75 ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6a 69 6e c7 45 ?? 6a 70 74 77}  //weight: 1, accuracy: Low
        $x_1_6 = {63 78 63 63 c7 45 ?? 74 76 62 7a}  //weight: 1, accuracy: Low
        $x_1_7 = {78 78 78 70 c7 45 ?? 72 6f 62 69}  //weight: 1, accuracy: Low
        $x_2_8 = {83 f8 04 76 ?? 66 83 bc ?? ?? ff ff ff 74 75 ?? 66 83 bc ?? ?? ff ff ff 69 75 ?? 66 83 bc ?? ?? ff ff ff 62 75 ?? 66 83 bc ?? ?? ff ff ff 2e}  //weight: 2, accuracy: Low
        $x_1_9 = {69 c0 e8 03 00 00 83 c4 10 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff d3}  //weight: 1, accuracy: Low
        $x_1_10 = ".\\NtSecureSys" ascii //weight: 1
        $x_1_11 = ".\\PCI#VEN_25AF&DEV_0209&SUBSYS_070455AF&REV_00" ascii //weight: 1
        $x_1_12 = "-set TESTSIGNING ON" ascii //weight: 1
        $x_1_13 = "/C del /Q /F \"%s\"" ascii //weight: 1
        $x_1_14 = "advfirewall firewall set rule name=\"%s\" dir=%s" ascii //weight: 1
        $x_1_15 = "firewall set opmode mode=DISABLE profile=ALL" ascii //weight: 1
        $x_1_16 = "%s\\drivers\\%s.sys" ascii //weight: 1
        $x_1_17 = {00 66 69 6e 64 6d 65}  //weight: 1, accuracy: High
        $x_1_18 = {00 65 69 6e 69 74}  //weight: 1, accuracy: High
        $x_1_19 = {00 64 65 6c 6d 65}  //weight: 1, accuracy: High
        $x_1_20 = "%s%08x-%04x-%04x-%04x-%08x%04x.tmp" ascii //weight: 1
        $x_1_21 = "%s%0.8X-%0.4X-%0.4X-%0.4X-%0.8X%0.4X}\\" ascii //weight: 1
        $x_1_22 = "%08x %swhen %s at %p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


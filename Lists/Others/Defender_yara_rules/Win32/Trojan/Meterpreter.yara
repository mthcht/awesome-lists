rule Trojan_Win32_Meterpreter_A_2147721925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A"
        threat_id = "2147721925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d9 74 24 f4 [0-16] 31 ?? ?? 83 ?? ?? 03 ?? ?? e2 f5}  //weight: 1, accuracy: Low
        $x_1_2 = {68 99 a5 74 61 ff d5 85 c0 74 0a ff 4e 08 75 ec}  //weight: 1, accuracy: High
        $x_1_3 = {5d 68 74 74 70 00 68 77 69 6e 68 54 68 ?? ?? ?? ?? ff d5 31 db 53 53 53 53 53 68 ?? ?? ?? ?? ff d5 53 68 52 11 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Meterpreter_I_2147723084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.I!attk"
        threat_id = "2147723084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 89 e5 83 ec 18 8b 45 08 89 45 f4 8b 45 f4 ff d0 90 c9}  //weight: 1, accuracy: High
        $x_1_2 = {00 5f 65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_J_2147723085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.J!attk"
        threat_id = "2147723085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 83 ec 28 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 45 f4 c7 45 f0 00 00 00 00 8b 45 f4 8d 55 f0 89 54 24 0c c7 44 24 08 40 00 00 00 89 44 24 04 8b 45 08 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 10 8b 45 08 ff d0 90 c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {00 5f 65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 36 34 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_F_2147723359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.F"
        threat_id = "2147723359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d dc 0d 7d 0d 8b 45 dc 80 74 28 ef ?? ff 45 dc eb ed}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 04 8d 45 8c 50 6a 07 68 ff ff ff ff ff 55 94 83 7d 8c 00 0f 84 0a 00 00 00 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {68 64 6e 73 61 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {50 68 6a c9 9c c9 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 f4 00 8e cc ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {68 2d 06 18 7b ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 12 96 89 e2 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hll Ah32.dhuser" ascii //weight: 1
        $x_1_2 = "hoxX hageBhMess" ascii //weight: 1
        $x_1_3 = {8b 45 3c 8b 54 28 78}  //weight: 1, accuracy: High
        $x_1_4 = {84 c0 74 07 c1 cf ?? 01 c7 eb f4 3b 7c 24 28 75 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02}  //weight: 1, accuracy: High
        $x_1_2 = {68 33 32 00 00 68 77 73 32 5f}  //weight: 1, accuracy: High
        $x_1_3 = {68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 ea 0f df e0 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 c2 eb 38 5f 48 89 c6 e8 ?? ?? ?? ?? b9 ea 0f df e0 48 89 c5 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b8 77 73 32 5f 33 32 2e 64}  //weight: 1, accuracy: High
        $x_1_3 = {b9 99 a5 74 61 e8}  //weight: 1, accuracy: High
        $x_1_4 = {b9 02 d9 c8 5f [0-4] e8}  //weight: 1, accuracy: Low
        $x_1_5 = {b9 58 a4 53 e5 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e}  //weight: 10, accuracy: Low
        $x_1_2 = {83 e8 05 c6 43 05 e9 89 43 06 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {c6 46 05 e9 2b c6 83 e8 05 89 46 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_A_2147723574_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 57 05 ff d6 50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 33 ce ff d6 89 e1 50 b4 0c 50 51 57 51 66 b9 c0 38 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad ad 4e 03 06 3d 32 33 5f 32 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = {8b 6b 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 8b 5c 29 3c 03 dd 03 6c 29 24 57}  //weight: 1, accuracy: High
        $x_1_3 = {8b f4 56 68 ?? ?? ?? ?? 57 ff d5 ad 85 c0 74 ee}  //weight: 1, accuracy: Low
        $x_2_4 = {ff d3 ad 3d ?? ?? ?? ?? 75 dd ff e6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_A_2147723574_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff}  //weight: 1, accuracy: High
        $x_1_2 = {5c 5c 2e 5c 70 69 70 65 [0-32] 68 da f6 da 4f ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 ad 9e 5f bb ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 [0-8] ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97}  //weight: 1, accuracy: High
        $x_1_4 = {6a 10 56 57 68 99 a5 74 61 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {bb f0 b5 a2 56 6a 00 53 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff e0 5f 5f 5a 8b 12 eb ?? 5d 6a 01 8d 85 9a 00 00 00 50 68 31 8b 6f 87 ff d5 68 47 13 72 6f ff d5}  //weight: 1, accuracy: Low
        $x_1_2 = {60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 c6 96 87 52 89 44 ?? ?? e8 [0-10] c7 04 24 4c 77 26 07}  //weight: 1, accuracy: Low
        $x_1_2 = {77 73 32 5f c7 44 24 ?? 33 32 2e 64 [0-6] c6 44 24 ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d0 83 ec 04 c7 04 24 99 a5 74 61 e8}  //weight: 1, accuracy: High
        $x_1_4 = {c7 04 24 52 f3 e2 51 e8 ?? ?? ?? ?? c7 04 24 5f 78 54 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {53 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {66 53 89 e1 6a 10 51 57 66 b9 80 3b ff d6}  //weight: 1, accuracy: High
        $x_1_4 = {66 b9 75 49 ff d6 54 54 54 57 66 b9 32 4c ff d6}  //weight: 1, accuracy: High
        $x_1_5 = {b4 0c 50 51 57 51 66 b9 c0 38 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0}  //weight: 1, accuracy: High
        $x_1_2 = {e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2}  //weight: 1, accuracy: High
        $x_1_3 = {50 68 31 8b 6f 87 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {bb e0 1d 2a 0a 68 a6 95 bd 9d ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {bb 47 13 72 6f 6a 00 53 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ba 02 d9 c8 5f ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {41 ba 75 6e 4d 61 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {41 ba 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9}  //weight: 1, accuracy: High
        $x_1_5 = {5d 49 be 77 73 32 5f 33 32 00 00 41 56}  //weight: 1, accuracy: High
        $x_1_6 = {41 ba ea 0f df e0 ff d5 [0-32] 41 ba 99 a5 74 61 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 db 64 8b 43 30 8b 40 0c 8b 50 1c 8b 12 8b 72 20 ad ad 4e 03 06 3d 32 33 5f 32}  //weight: 2, accuracy: High
        $x_2_2 = {8b 6a 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 01 e9 8b 41 58 01 e8 8b 71 3c 01 ee 03 69 0c 53 6a 01 6a 02 ff d0}  //weight: 2, accuracy: High
        $x_1_3 = {68 02 00 11 5c 89 e1 53 b7 0c}  //weight: 1, accuracy: High
        $x_1_4 = {53 51 57 51 6a 10 51 57 56 ff e5}  //weight: 1, accuracy: High
        $x_1_5 = "http:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_A_2147723574_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 c7 c2 2d 06 18 7b ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {49 ba 58 a4 53 e5 00 00 00 00 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {49 ba 12 96 89 e2 00 00 00 00 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {49 c7 c2 f0 b5 a2 56 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9}  //weight: 1, accuracy: High
        $x_1_6 = {49 be 77 69 6e 69 6e 65 74 00 [0-8] 49 c7 c2 4c 77 26 07 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 c7 c2 6c 29 24 7e ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {49 c7 c2 05 88 9d 70 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {49 ba 95 58 bb 91 00 00 00 00 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {49 ba d3 58 9d ce 00 00 00 00 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9}  //weight: 1, accuracy: High
        $x_1_6 = {49 be 77 69 6e 68 74 74 70 00 [0-8] 49 c7 c2 4c 77 26 07 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {95 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 a8 6f ff d6 97 68 0a 0a 01 15}  //weight: 1, accuracy: High
        $x_1_4 = {66 b9 a8 6f ff d6 97 68 c0 a8 01 07}  //weight: 1, accuracy: High
        $x_1_5 = {66 53 89 e3 6a 10 53 57 66 b9 57 05 ff d6}  //weight: 1, accuracy: High
        $x_1_6 = {50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 52 60 [0-4] 48 8b 52 18 [0-4] 48 8b 52 20}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 41 59 68 00 10 00 00 41 58 48 89 f2 48 31 c9 41 ba 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 48 89 f9 41 ba ad 9e 5f bb ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 59 49 c7 c2 f0 b5 a2 56 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = "\\\\.\\pipe\\" ascii //weight: 1
        $x_1_6 = {6a 00 59 bb e0 1d 2a 0a 41 89 da ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 8d 85 b2 00 00 00 50 68 31 8b 6f 87 ff}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 20 75 73 65 72 20 20 00 20 [0-32] 20 2f 61 64 64 20 26 26 20 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 20 00 20 2f 61 64 64}  //weight: 1, accuracy: Low
        $x_1_3 = {66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed}  //weight: 1, accuracy: High
        $x_1_2 = {e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8}  //weight: 1, accuracy: High
        $x_1_3 = {41 ba 31 8b 6f 87 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {bb e0 1d 2a 0a 41 ba a6 95 bd 9d ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {86 c6 c2 04 18 33 32 2e 64 87 57 36 57 32}  //weight: 1, accuracy: High
        $x_2_2 = {bb a8 a2 4d bc 87 1c 24 52}  //weight: 2, accuracy: High
        $x_2_3 = "hoxX hageBhMess" ascii //weight: 2
        $x_1_4 = {68 8e 4e 0e ec 52 e8}  //weight: 1, accuracy: High
        $x_1_5 = {88 4c 24 10 89 e1 31 d2 52 53 51 52 ff d0 31 c0 50 ff 55 08}  //weight: 1, accuracy: High
        $x_1_6 = {8b 6c 24 24 8b 45 3c 8b 54 28 78 01 ea 8b 4a 18 8b 5a 20 01 eb e3 34 49 8b 34 8b 01 ee 31 ff 31 c0 fc ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_A_2147723574_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02}  //weight: 1, accuracy: High
        $x_1_2 = {5c 5c 2e 5c 70 69 70 65 [0-32] 68 45 70 df d4 ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 ad 9e 5f bb ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5}  //weight: 1, accuracy: High
        $x_1_6 = {ff e1 e8 00 00 00 00 bb f0 b5 a2 56 6a 00 53 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {b8 04 02 00 00 29 c4 48 48 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {50 50 50 6a 06 40 50 6a 17 68 ea 0f df e0}  //weight: 1, accuracy: High
        $x_1_4 = {ff d5 89 c7 6a 1c e8 1c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 68 99 a5 74 61 ff d5}  //weight: 1, accuracy: High
        $x_1_6 = {6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5}  //weight: 1, accuracy: High
        $x_1_7 = {68 00 10 00 00 56 6a 00 68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_26
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec 74 ?? ?? ?? ?? aa fc 0d 7c 74 ?? ?? ?? ?? 54 ca af 91 74 ?? ?? ?? ?? ef ce e0 60}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 0a 4c 53 75}  //weight: 1, accuracy: High
        $x_1_6 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-16] ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_27
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_2_2 = {50 68 57 89 9f c6 ff d5}  //weight: 2, accuracy: High
        $x_1_3 = {68 2d 06 18 7b ff d5 85 c0}  //weight: 1, accuracy: High
        $x_2_4 = {68 12 96 89 e2 ff d5 85 c0}  //weight: 2, accuracy: High
        $x_1_5 = {50 6a 02 6a 02 57 68 da f6 da 4f ff d5}  //weight: 1, accuracy: High
        $x_4_6 = {6a 00 57 68 31 8b 6f 87 ff d5}  //weight: 4, accuracy: High
        $x_1_7 = {6a 00 68 f0 b5 a2 56 ff d5}  //weight: 1, accuracy: High
        $x_1_8 = {58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_A_2147723574_28
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {68 a6 95 bd 9d ff d3 3c 06 7c 1a 31 c9 64 8b 41 18 39 88 a8 01 00 00 75 0c 8d 93 cf 00 00 00 89 90 a8 01 00 00 31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9}  //weight: 1, accuracy: High
        $x_1_3 = "StagelessInit" ascii //weight: 1
        $x_1_4 = "GET /123456789" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_29
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 6a 30 59 64 8b 19 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08}  //weight: 1, accuracy: High
        $x_1_2 = {57 53 32 5f 33 32 00 5b 8d 4b 20 51 ff d7}  //weight: 1, accuracy: High
        $x_1_3 = {77 73 32 5f 33 32 00 5b 8d 4b 20 51 ff d7}  //weight: 1, accuracy: High
        $x_1_4 = {49 8b 34 8b 01 ee 31 ff fc 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2}  //weight: 1, accuracy: High
        $x_1_5 = {a4 1a 70 c7 a4 ad 2e e9}  //weight: 1, accuracy: High
        $x_2_6 = {ff 55 24 53 57 ff 55 28 53 54 57 ff 55 20 89 c7 68 43 4d 44 00}  //weight: 2, accuracy: High
        $x_1_7 = {ff 75 00 68 72 fe b3 16 ff 55 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_A_2147723574_30
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 00 68 77 69 6e 68 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {68 04 1f 9d bb ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {50 68 46 9b 1e c2 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 01 00 00 53 53 53 57 53 50 68 98 10 b3 5b ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {53 53 53 53 53 53 56 68 95 58 bb 91 ff d5}  //weight: 1, accuracy: High
        $x_1_6 = {53 56 68 05 88 9d 70 ff d5}  //weight: 1, accuracy: High
        $x_1_7 = {6a 40 68 00 10 00 00 68 00 00 40 00 53 68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_8 = {57 68 00 20 00 00 53 56 68 6c 29 24 7e ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_31
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07}  //weight: 1, accuracy: High
        $x_1_2 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 1, accuracy: High
        $x_1_4 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 ?? ff 4e 08 75}  //weight: 1, accuracy: Low
        $x_1_5 = {68 58 a4 53 e5 ff d5 [0-10] 6a 00 56 53 57 68 02 d9 c8 5f ff d5}  //weight: 1, accuracy: Low
        $x_1_6 = {89 e6 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_32
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb}  //weight: 1, accuracy: High
        $x_1_3 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {68 2d 06 18 7b ff d5 85 c0 75 [0-8] eb ?? eb ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 e8 ?? ?? 00 00 68 74 74 70 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_33
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 8b 80 88 00 00 00 48 85 c0 74}  //weight: 1, accuracy: High
        $x_1_2 = {ff e0 58 41 59 5a 48 8b 12 e9 ?? ?? ?? ?? 5d 48 ba 01 00 00 00 00 00 00 00 48 8d 8d ?? ?? 00 00 41 ba 31 8b 6f 87 ff d5 bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_34
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 04 8d 5a 04 53 ff 12 c2 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 04 8b 5a 04 8d 4a 08 51 53 ff 12 c2 04 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 54 24 04 ff 72 04 ff 12 c2 04 00}  //weight: 1, accuracy: High
        $x_1_4 = "stdapi_net_tcp_client" ascii //weight: 1
        $x_1_5 = "stdapi_net_tcp_server" ascii //weight: 1
        $x_1_6 = "stdapi_net_udp_client" ascii //weight: 1
        $x_1_7 = "stdapi_fs_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_35
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3}  //weight: 1, accuracy: High
        $x_1_2 = {ff e0 5f 5f 5a 8b 12 eb ?? 5d 6a 01 8d 85 ?? 00 00 00 50 68 31 8b 6f 87 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 47 13 72 6f 6a 00 53 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {ff e0 5f 5f 5a 8b 12 eb 8d 5d 8d 85 ?? 00 00 00 50 68 4c 77 26 07 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_36
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 e3 81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5d 68 fa 3c 75 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 0a 4c 53 75 21 8b 45 ?? 0f b7}  //weight: 1, accuracy: Low
        $x_1_4 = {8e 4e 0e ec 74 [0-3] aa fc 0d 7c 74 [0-3] 54 ca af 91 74 [0-3] 1b c6 46 79 74 [0-3] f2 32 f6 0e 75}  //weight: 1, accuracy: Low
        $x_1_5 = {64 a1 30 00 00 00 6a 04 89 75 f8 c7 45 d4 02 00 00 00 8b 40 0c c7 45 c8 01 00 00 00 8b 58 14 89 5d ec 58 85 db}  //weight: 1, accuracy: High
        $x_1_6 = {8b 77 28 33 ff 57 57 6a ff 03 f3 ff 55 d8 33 c0 57 40 50 53 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_37
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_ReflectiveLoader@" ascii //weight: 1
        $x_1_2 = {75 e3 81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec 74 [0-3] aa fc 0d 7c 74 [0-3] 54 ca af 91 74 [0-3] f2 32 f6 0e 75}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 5d 68 fa 3c 75 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 0a 4c 53 75 21 8b 45 ?? 0f b7}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 5e 3c 6a 40 03 de 68 00 30 00 00 89 5d f0 ff 73 50 6a 00 ff}  //weight: 1, accuracy: High
        $x_1_7 = {8b 5d f0 8b 73 28 33 db 53 53 6a ff 03 f7 ff 55 dc 33 c0 53 40 50 57 ff d6 5f 8b c6 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_38
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 db 53 53 53 53 53 68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb}  //weight: 1, accuracy: High
        $x_1_4 = {68 2d 06 18 7b ff d5 85 c0 75 ?? 68 88 13 00 00 68 44 f0 35 e0 ff d5 4f 75}  //weight: 1, accuracy: Low
        $x_1_5 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_6 = {68 2d 06 18 7b ff d5 85 c0 75 [0-32] 68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_39
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec 74 [0-4] aa fc 0d 7c 74 [0-4] 54 ca af 91 74 [0-4] f2 32 f6 0e 75}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 0a 4c 53 75}  //weight: 1, accuracy: High
        $x_1_6 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-4] ff d6}  //weight: 1, accuracy: Low
        $x_1_7 = {41 8b 5f 28 45 33 c0 33 d2 48 83 c9 ff 49 03 de ff 54 24 68 45 33 c0 49 8b ce 41 8d 50 01 ff d3 48 8b c3 48 83 c4 40 41 5f 41 5e 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_40
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec 74 [0-4] aa fc 0d 7c 74 [0-4] 54 ca af 91 74 [0-4] f2 32 f6 0e 75}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 0a 4c 53 75}  //weight: 1, accuracy: High
        $x_1_6 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-4] ff d6}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 5e 28 45 33 c0 33 d2 48 83 c9 ff 48 03 df ff 54 24 70 45 33 c0 48 8b cf 41 8d 50 01 ff d3 48 8b c3 48 83 c4 28 41 5f 41 5e 41 5d 41 5c 5f 5e 5d 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_41
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a e8 00 00 00 00 5b 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 81 c3 ?? ?? ?? ?? 89 3b 53 6a 04 50 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 fc 8b 5e 3c 6a 40 03 de 68 00 30 00 00 89 5d f0 ff 73 50 6a 00 ff 55 ec ff 73 50 8b f8 57 89 7d f4 ff 55 e8 8b 53 54 8b ce 85 d2 74 12 8b c7 2b c6 89 45 d8 8b f0 8a 01 88 04 0e 41 4a 75 f7}  //weight: 1, accuracy: High
        $x_1_3 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_42
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02}  //weight: 1, accuracy: High
        $x_1_3 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1}  //weight: 1, accuracy: High
        $x_1_4 = {f0 b5 a2 56}  //weight: 1, accuracy: High
        $x_1_5 = "webcam_audio_record" ascii //weight: 1
        $x_1_6 = "%TEMP%\\hook.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_43
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 76 30 8b 76 0c 8b 76 1c 56 ?? ?? ?? ?? 5f 8b 6f 08 ff 37 8b 5d 3c 8b 5c 1d 78 01 eb 8b 4b 18 67 e3 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {32 17 66 c1 ca 01 ae 75 f7 49 66 39 f2 74 08 67 e3 cb}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 fa da f0 74 1b 66 81 fa 69 27 74 20 6a 32 68 6f 6c 65 33 54 ff d7}  //weight: 1, accuracy: High
        $x_1_4 = {68 6e 04 22 d4 68 a1 ec ef 99 68 b9 72 92 49 68 74 df 44 6c}  //weight: 1, accuracy: High
        $x_1_5 = {68 4f 79 73 96 68 9e e3 01 c0}  //weight: 1, accuracy: High
        $x_1_6 = {68 91 33 d2 11 68 77 93 74 96}  //weight: 1, accuracy: High
        $x_1_7 = {89 e3 56 54 50 6a 17 56 53 ff d7}  //weight: 1, accuracy: High
        $x_2_8 = "hog Uhop th!dnh" ascii //weight: 2
        $x_1_9 = {ac 66 50 3c 55 75 f9 89 e1 31 c0 50 50 51 53 8b 13 8b 4a 50 ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_A_2147723574_44
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e}  //weight: 1, accuracy: Low
        $x_1_3 = {f0 b5 a2 56}  //weight: 1, accuracy: High
        $x_1_4 = {fe 0e 32 ea 75}  //weight: 1, accuracy: High
        $x_1_5 = "mimikatz_custom_command" ascii //weight: 1
        $x_1_6 = "\\\\.\\mimikatz" wide //weight: 1
        $x_1_7 = "KiwiAndRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_45
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb}  //weight: 1, accuracy: High
        $x_1_4 = {68 58 a4 53 e5 ff d5 [0-16] 6a 00 56 53 57 68 02 d9 c8 5f ff d5}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 ?? ff 4e 08 75}  //weight: 1, accuracy: Low
        $x_1_6 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 89 e8 ff d0 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_7 = {68 b7 e9 38 ff ff d5 [0-8] 68 74 ec 3b e1 ff d5 [0-8] 68 75 6e 4d 61 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_46
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e}  //weight: 1, accuracy: Low
        $x_1_3 = {f0 b5 a2 56}  //weight: 1, accuracy: High
        $x_1_4 = {fe 0e 32 ea 75}  //weight: 1, accuracy: High
        $x_1_5 = {6d 65 74 73 72 76 2e 64 6c 6c 00 00 52 74 6c 43 72 65 61 74 65 55 73 65 72 54 68 72 65 61 64}  //weight: 1, accuracy: High
        $x_1_6 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 00 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 25 73 20 3e 20 25 73 00 25 73 25 73 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_7 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 61 20 2f 70 3a 25 73 00 2f 74 3a 30 78 25 30 38 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_47
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PAYLOAD_UUID =" ascii //weight: 1
        $x_1_2 = "super(MeterpreterFile, self).__init__()" ascii //weight: 1
        $x_1_3 = "super(MeterpreterProcess, self).__init__()" ascii //weight: 1
        $x_1_4 = "export(MeterpreterSocketTCPServer)" ascii //weight: 1
        $x_1_5 = "class PythonMeterpreter(object):" ascii //weight: 1
        $x_1_6 = "met = PythonMeterpreter(transport)" ascii //weight: 1
        $x_1_7 = "met.run()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_48
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 17 59 89 cf 31 d2 52 52 6a 03 52 6a 03 68 00 00 00 c0 56 8b 5d 14 ff d3}  //weight: 1, accuracy: High
        $x_1_2 = {52 8d 5c 24 04 53 52 52 52 52 68 20 00 09 00 50 8b 5d 08 ff d3}  //weight: 1, accuracy: High
        $x_2_3 = {68 00 10 00 00 6a 01 8d 86 1a 00 00 00 50 8d 86 10 00 00 00 50 6a 0c 8d 46 08 50 8b 5d 00 ff d3}  //weight: 2, accuracy: High
        $x_1_4 = {68 c8 00 00 00 8b 5d 04 ff d3 89 f9 83 46 08 01 e2 8d 6a 00 8b 5d 10 ff d3}  //weight: 1, accuracy: High
        $x_1_5 = {66 6d 69 66 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 50 08 8b 78 20 8b 00 3a 4f 18 75 f3}  //weight: 1, accuracy: High
        $x_3_7 = {68 64 5b 02 ab 68 10 a1 67 05 68 a7 d4 34 3b}  //weight: 3, accuracy: High
        $x_1_8 = {68 96 90 62 d7 68 87 8f 46 ec 68 06 e5 b0 cf 68 dc dd 1a 33}  //weight: 1, accuracy: High
        $x_1_9 = {83 f9 01 75 0c 51 eb 1c 8b 44 24 1c ff d0 89 c2 59 51 8b 4c bd 00 e8 ?? ?? ?? ?? 59 50 47 e2 e0 89 e5 eb 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_A_2147723574_49
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\pipe\\spoolss" ascii //weight: 1
        $x_1_2 = {73 61 6d 73 72 76 2e 64 6c 6c [0-32] 53 61 6d 49 43 6f 6e 6e 65 63 74 [0-32] 53 61 6d 72 4f 70 65 6e 44 6f 6d 61 69 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {47 6c 6f 62 61 6c 5c 53 41 4d [0-32] 47 6c 6f 62 61 6c 5c 46 52 45 45}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6a 00 68 ff 00 0f 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8d 45 dc 50 6a 02 ff 75 f4 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 40 68 00 10 00 00 ff 75 f0 6a 00 53 ff 15 ?? ?? ?? ?? 89 45 dc 85 c0 ?? ?? 8d 4d ?? 51 ff 75 f0 68 6a 2f 00 10 50 53 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_6 = {6c 73 61 73 73 2e 65 78 65 [0-32] 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65}  //weight: 1, accuracy: Low
        $x_1_7 = "cmd.exe /c echo %s > %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_50
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\pipe\\spoolss" ascii //weight: 1
        $x_1_2 = {73 61 6d 73 72 76 2e 64 6c 6c [0-32] 53 61 6d 49 43 6f 6e 6e 65 63 74 [0-32] 53 61 6d 72 4f 70 65 6e 44 6f 6d 61 69 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {47 6c 6f 62 61 6c 5c 53 41 4d [0-32] 47 6c 6f 62 61 6c 5c 46 52 45 45}  //weight: 1, accuracy: Low
        $x_1_4 = {45 33 c0 48 8b c8 ba ff 00 0f 00 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 4c 24 48 4c 8d ?? ?? ?? ba 02 00 00 00 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {45 8b fe c7 44 24 20 04 00 00 00 41 b9 00 30 00 00 45 8b c6 33 d2 48 8b cf ff 15 ?? ?? ?? ?? 4c 8b f0 48 85 c0 ?? ?? 48 89 5c 24 20 45 8b cf 4c 8b c6 48 8b d0 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {6c 73 61 73 73 2e 65 78 65 [0-32] 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65}  //weight: 1, accuracy: Low
        $x_1_7 = "cmd.exe /c echo %s > %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_51
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a 41 52 55 48 89 e5 48 83 ec 20 48 83 e4 f0 e8 00 00 00 00 5b 48 81 c3 ?? ?? ?? ?? ff d3 48 81 c3 ?? ?? ?? ?? 48 89 3b 49 89 d8 6a 04 5a ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 9c 24 88 00 00 00 48 63 73 3c 33 c9 41 b8 00 30 00 00 48 03 f3 44 8d 49 40 8b 56 50 41 ff d6 8b 56 50 48 8b c8 48 8b f8 41 ff d7 8b 56 54 48 8b cb 41 bb 01 00 00 00 48 85 d2 74 14 4c 8b c7 4c 2b c3 8a 01 41 88 04 08 49 03 cb 49 2b d3 75 f2 44 0f b7 4e 06 0f b7 46 14 4d 85 c9 74 38 48 8d 4e 2c 48 03 c8 8b 51 f8 44 8b 01 44 8b 51 fc 48 03 d7 4c 03 c3 4d 2b cb 4d 85 d2 74 10 41 8a 00 4d 03 c3 88 02 49 03 d3 4d 2b d3 75 f0}  //weight: 1, accuracy: High
        $x_1_3 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_52
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[System.Convert]::FromBase64String(\"/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/" ascii //weight: 1
        $x_1_2 = {3a 3a 47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 28 28 [0-8] 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 29 2c 20 28 [0-8] 20 40 28 5b 49 6e 74 50 74 72 5d 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3a 3a 47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 28 28 [0-8] 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 43 72 65 61 74 65 54 68 72 65 61 64 29 2c 20 28 [0-8] 20 40 28 5b 49 6e 74 50 74 72 5d 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 29 2c 20 28 [0-8] 20 40 28 5b 49 6e 74 50 74 72 5d 2c 20 5b 49 6e 74 33 32 5d 29 29 29 2e 49 6e 76 6f 6b 65 28 24 [0-8] 2c 30 78 66 66 66 66 66 66 66 66 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_A_2147723574_53
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147723574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 89 e5 56 57 8b 75 08 8b 4d 0c e8 00 00 00 00 58 83 c0 2b 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 0f 00 00 00 66 8c d8 66 8e d0 83 c4 14 5f 5e 5d c2 08 00 8b 3c e4 ff 2a 48 31 c0 57 ff d6 5f 50 c7 44 24 04 23 00 00 00 89 3c 24 ff 2c 24}  //weight: 1, accuracy: High
        $x_1_2 = {fc 48 89 ce 48 89 e7 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 75 72 8b 80 88 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 85 c0 74 67 48 01 d0 50 8b 48 18 44 8b 40 20 49 01 d0 e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 58 44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 4f ff ff ff 5d 4d 31 c9 41 51 48 8d 46 18 50 ff 76 10 ff 76 08 41 51 41 51 49 b8 01 00 00 00 00 00 00 00 48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c 48 b8 00 00 00 00 00 00 00 00 eb 0a 48 b8 01 00 00 00 00 00 00 00 48 83 c4 50 48 89 fc c3}  //weight: 1, accuracy: High
        $x_1_4 = {fc 80 79 10 00 0f 85 13 01 00 00 c6 41 10 01 48 83 ec 78 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 75 72 8b 80 88 00 00 00 48 85 c0 74 67 48 01 d0 50 8b 48 18 44 8b 40 20 49 01 d0 e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38}  //weight: 1, accuracy: High
        $x_1_5 = {e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 58 44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 4f ff ff ff 5d 48 31 d2 65 48 8b 42 30 48 39 90 c8 02 00 00 75 0e 48 8d 95 07 01 00 00 48 89 90 c8 02 00 00 4c 8b 01 4c 8b 49 08 48 31 c9 48 31 d2 51 51 41 ba 38 68 0d 16 ff d5 48 81 c4 a8 00 00 00 c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {78 46 43 8b 74 24 04 55 89 e5 e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4a 01 d0 50 8b 48 18 8b 58 20 01 d3 e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 eb 86 5b 80 7e 10 00 75 3b c6 46 10 01 68 a6 95 bd 9d ff d3 3c 06 7c 1a 31 c9 64 8b 41 18 39 88 a8 01 00 00 75 0c 8d 93 cf 00 00 00 89 90 a8 01 00 00 31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9 c2 0c 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02}  //weight: 1, accuracy: High
        $x_1_2 = {68 33 32 00 00 68 77 73 32 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 c2 eb 38 5f 48 89 c6 e8 ?? ?? ?? ?? b9 ea 0f df e0 48 89 c5 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b8 77 73 32 5f 33 32 2e 64}  //weight: 1, accuracy: High
        $x_1_3 = {b9 99 a5 74 61 e8}  //weight: 1, accuracy: High
        $x_1_4 = {b9 02 d9 c8 5f [0-4] e8}  //weight: 1, accuracy: Low
        $x_1_5 = {b9 58 a4 53 e5 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5f 5a 8b 12 eb ?? 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5}  //weight: 2, accuracy: Low
        $x_1_2 = {68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {68 2d 06 18 7b ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 12 96 89 e2 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff}  //weight: 1, accuracy: High
        $x_1_2 = {5c 5c 2e 5c 70 69 70 65 [0-32] 68 da f6 da 4f ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 ad 9e 5f bb ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 2d 06 18 7b ff d5 85 c0 75}  //weight: 1, accuracy: High
        $x_1_2 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02}  //weight: 1, accuracy: High
        $x_1_2 = {5c 5c 2e 5c 70 69 70 65 [0-32] 68 45 70 df d4 ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 ad 9e 5f bb ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5}  //weight: 1, accuracy: High
        $x_1_6 = {ff e1 e8 00 00 00 00 bb f0 b5 a2 56 6a 00 53 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb}  //weight: 1, accuracy: High
        $x_1_3 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {68 2d 06 18 7b ff d5 85 c0 75 [0-8] eb ?? eb ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 e8 ?? ?? 00 00 68 74 74 70 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 db 53 53 53 53 53 68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb}  //weight: 1, accuracy: High
        $x_1_4 = {68 2d 06 18 7b ff d5 85 c0 75 ?? 68 88 13 00 00 68 44 f0 35 e0 ff d5 4f 75}  //weight: 1, accuracy: Low
        $x_1_5 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_6 = {68 2d 06 18 7b ff d5 85 c0 75 [0-32] 68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb}  //weight: 1, accuracy: High
        $x_1_4 = {68 58 a4 53 e5 ff d5 [0-16] 6a 00 56 53 57 68 02 d9 c8 5f ff d5}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 ?? ff 4e 08 75}  //weight: 1, accuracy: Low
        $x_1_6 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 89 e8 ff d0 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_7 = {68 b7 e9 38 ff ff d5 [0-8] 68 74 ec 3b e1 ff d5 [0-8] 68 75 6e 4d 61 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_C_2147725332_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!C"
        threat_id = "2147725332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[System.Convert]::FromBase64String(\"/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/" ascii //weight: 1
        $x_1_2 = {3a 3a 47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 28 28 [0-8] 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 29 2c 20 28 [0-8] 20 40 28 5b 49 6e 74 50 74 72 5d 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {3a 3a 47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 28 28 [0-8] 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 43 72 65 61 74 65 54 68 72 65 61 64 29 2c 20 28 [0-8] 20 40 28 5b 49 6e 74 50 74 72 5d 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 29 2c 20 28 [0-8] 20 40 28 5b 49 6e 74 50 74 72 5d 2c 20 5b 49 6e 74 33 32 5d 29 29 29 2e 49 6e 76 6f 6b 65 28 24 [0-8] 2c 30 78 66 66 66 66 66 66 66 66 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_L_2147725362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.L"
        threat_id = "2147725362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02}  //weight: 1, accuracy: High
        $x_1_3 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1}  //weight: 1, accuracy: High
        $x_1_4 = {f0 b5 a2 56}  //weight: 1, accuracy: High
        $x_1_5 = "webcam_audio_record" ascii //weight: 1
        $x_1_6 = "%TEMP%\\hook.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_L_2147725362_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.L"
        threat_id = "2147725362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e}  //weight: 1, accuracy: Low
        $x_1_3 = {f0 b5 a2 56}  //weight: 1, accuracy: High
        $x_1_4 = {fe 0e 32 ea 75}  //weight: 1, accuracy: High
        $x_1_5 = "mimikatz_custom_command" ascii //weight: 1
        $x_1_6 = "\\\\.\\mimikatz" wide //weight: 1
        $x_1_7 = "KiwiAndRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_L_2147725362_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.L"
        threat_id = "2147725362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e}  //weight: 1, accuracy: Low
        $x_1_3 = {f0 b5 a2 56}  //weight: 1, accuracy: High
        $x_1_4 = {fe 0e 32 ea 75}  //weight: 1, accuracy: High
        $x_1_5 = {6d 65 74 73 72 76 2e 64 6c 6c 00 00 52 74 6c 43 72 65 61 74 65 55 73 65 72 54 68 72 65 61 64}  //weight: 1, accuracy: High
        $x_1_6 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 00 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 25 73 20 3e 20 25 73 00 25 73 25 73 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_7 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 61 20 2f 70 3a 25 73 00 2f 74 3a 30 78 25 30 38 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_E_2147727230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!E"
        threat_id = "2147727230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07}  //weight: 1, accuracy: High
        $x_1_2 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 1, accuracy: High
        $x_1_4 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 ?? ff 4e 08 75}  //weight: 1, accuracy: Low
        $x_1_5 = {68 58 a4 53 e5 ff d5 [0-10] 6a 00 56 53 57 68 02 d9 c8 5f ff d5}  //weight: 1, accuracy: Low
        $x_1_6 = {89 e6 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_F_2147727241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!F"
        threat_id = "2147727241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 [0-8] ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97}  //weight: 1, accuracy: High
        $x_1_4 = {6a 10 56 57 68 99 a5 74 61 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {bb f0 b5 a2 56 6a 00 53 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_G_2147727245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!G"
        threat_id = "2147727245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 00 68 77 69 6e 68 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {68 04 1f 9d bb ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {50 68 46 9b 1e c2 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 01 00 00 53 53 53 57 53 50 68 98 10 b3 5b ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {53 53 53 53 53 53 56 68 95 58 bb 91 ff d5}  //weight: 1, accuracy: High
        $x_1_6 = {53 56 68 05 88 9d 70 ff d5}  //weight: 1, accuracy: High
        $x_1_7 = {6a 40 68 00 10 00 00 68 00 00 40 00 53 68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_8 = {57 68 00 20 00 00 53 56 68 6c 29 24 7e ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_H_2147727254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!H"
        threat_id = "2147727254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {53 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {66 53 89 e1 6a 10 51 57 66 b9 80 3b ff d6}  //weight: 1, accuracy: High
        $x_1_4 = {66 b9 75 49 ff d6 54 54 54 57 66 b9 32 4c ff d6}  //weight: 1, accuracy: High
        $x_1_5 = {b4 0c 50 51 57 51 66 b9 c0 38 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_I_2147727257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!I"
        threat_id = "2147727257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 db 64 8b 43 30 8b 40 0c 8b 50 1c 8b 12 8b 72 20 ad ad 4e 03 06 3d 32 33 5f 32}  //weight: 2, accuracy: High
        $x_2_2 = {8b 6a 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 01 e9 8b 41 58 01 e8 8b 71 3c 01 ee 03 69 0c 53 6a 01 6a 02 ff d0}  //weight: 2, accuracy: High
        $x_1_3 = {68 02 00 11 5c 89 e1 53 b7 0c}  //weight: 1, accuracy: High
        $x_1_4 = {53 51 57 51 6a 10 51 57 56 ff e5}  //weight: 1, accuracy: High
        $x_1_5 = "http:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_K_2147727308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!K"
        threat_id = "2147727308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 57 05 ff d6 50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_K_2147727308_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!K"
        threat_id = "2147727308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 33 ce ff d6 89 e1 50 b4 0c 50 51 57 51 66 b9 c0 38 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_K_2147727308_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!K"
        threat_id = "2147727308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {95 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 a8 6f ff d6 97 68 0a 0a 01 15}  //weight: 1, accuracy: High
        $x_1_4 = {66 b9 a8 6f ff d6 97 68 c0 a8 01 07}  //weight: 1, accuracy: High
        $x_1_5 = {66 53 89 e3 6a 10 53 57 66 b9 57 05 ff d6}  //weight: 1, accuracy: High
        $x_1_6 = {50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_L_2147727867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!L"
        threat_id = "2147727867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 6a 30 59 64 8b 19 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08}  //weight: 1, accuracy: High
        $x_1_2 = {57 53 32 5f 33 32 00 5b 8d 4b 20 51 ff d7}  //weight: 1, accuracy: High
        $x_1_3 = {77 73 32 5f 33 32 00 5b 8d 4b 20 51 ff d7}  //weight: 1, accuracy: High
        $x_1_4 = {49 8b 34 8b 01 ee 31 ff fc 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2}  //weight: 1, accuracy: High
        $x_1_5 = {a4 1a 70 c7 a4 ad 2e e9}  //weight: 1, accuracy: High
        $x_2_6 = {ff 55 24 53 57 ff 55 28 53 54 57 ff 55 20 89 c7 68 43 4d 44 00}  //weight: 2, accuracy: High
        $x_1_7 = {ff 75 00 68 72 fe b3 16 ff 55 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_M_2147727987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.M!bit"
        threat_id = "2147727987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 10 89 45 f8 03 45 14 89 45 fc 8b 75 10 8a 06 88 45 f7 8b 4d 0c 8b 75 08 8b 7d 08 8a 06 46 51 8a 4d f7 d2 c0 59 50 56 ff 45 f8 8b 75 f8 8a 06 46 8b 5d fc 39 5d f8 75 0c 8b 55 10 89 55 f8 8b 75 f8 8a 06 46 88 45 f7 5e 58 88 07 47 49 83 f9 00 75 c9}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 e8 ?? ?? ?? 00 6a 00 e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff 75 a8 ff 15 ?? ?? ?? 00 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_M_2147728094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!M"
        threat_id = "2147728094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 8d 85 b2 00 00 00 50 68 31 8b 6f 87 ff}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 20 75 73 65 72 20 20 00 20 [0-32] 20 2f 61 64 64 20 26 26 20 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 20 00 20 2f 61 64 64}  //weight: 1, accuracy: Low
        $x_1_3 = {66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_N_2147728142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!N"
        threat_id = "2147728142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 17 59 89 cf 31 d2 52 52 6a 03 52 6a 03 68 00 00 00 c0 56 8b 5d 14 ff d3}  //weight: 1, accuracy: High
        $x_1_2 = {52 8d 5c 24 04 53 52 52 52 52 68 20 00 09 00 50 8b 5d 08 ff d3}  //weight: 1, accuracy: High
        $x_2_3 = {68 00 10 00 00 6a 01 8d 86 1a 00 00 00 50 8d 86 10 00 00 00 50 6a 0c 8d 46 08 50 8b 5d 00 ff d3}  //weight: 2, accuracy: High
        $x_1_4 = {68 c8 00 00 00 8b 5d 04 ff d3 89 f9 83 46 08 01 e2 8d 6a 00 8b 5d 10 ff d3}  //weight: 1, accuracy: High
        $x_1_5 = {66 6d 69 66 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 50 08 8b 78 20 8b 00 3a 4f 18 75 f3}  //weight: 1, accuracy: High
        $x_3_7 = {68 64 5b 02 ab 68 10 a1 67 05 68 a7 d4 34 3b}  //weight: 3, accuracy: High
        $x_1_8 = {68 96 90 62 d7 68 87 8f 46 ec 68 06 e5 b0 cf 68 dc dd 1a 33}  //weight: 1, accuracy: High
        $x_1_9 = {83 f9 01 75 0c 51 eb 1c 8b 44 24 1c ff d0 89 c2 59 51 8b 4c bd 00 e8 ?? ?? ?? ?? 59 50 47 e2 e0 89 e5 eb 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_O_2147728145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!O"
        threat_id = "2147728145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_2_2 = {50 68 57 89 9f c6 ff d5}  //weight: 2, accuracy: High
        $x_1_3 = {68 2d 06 18 7b ff d5 85 c0}  //weight: 1, accuracy: High
        $x_2_4 = {68 12 96 89 e2 ff d5 85 c0}  //weight: 2, accuracy: High
        $x_1_5 = {50 6a 02 6a 02 57 68 da f6 da 4f ff d5}  //weight: 1, accuracy: High
        $x_4_6 = {6a 00 57 68 31 8b 6f 87 ff d5}  //weight: 4, accuracy: High
        $x_1_7 = {6a 00 68 f0 b5 a2 56 ff d5}  //weight: 1, accuracy: High
        $x_1_8 = {58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_P_2147728159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!P"
        threat_id = "2147728159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {86 c6 c2 04 18 33 32 2e 64 87 57 36 57 32}  //weight: 1, accuracy: High
        $x_2_2 = {bb a8 a2 4d bc 87 1c 24 52}  //weight: 2, accuracy: High
        $x_2_3 = "hoxX hageBhMess" ascii //weight: 2
        $x_1_4 = {68 8e 4e 0e ec 52 e8}  //weight: 1, accuracy: High
        $x_1_5 = {88 4c 24 10 89 e1 31 d2 52 53 51 52 ff d0 31 c0 50 ff 55 08}  //weight: 1, accuracy: High
        $x_1_6 = {8b 6c 24 24 8b 45 3c 8b 54 28 78 01 ea 8b 4a 18 8b 5a 20 01 eb e3 34 49 8b 34 8b 01 ee 31 ff 31 c0 fc ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_Q_2147728162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!Q"
        threat_id = "2147728162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad ad 4e 03 06 3d 32 33 5f 32 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = {8b 6b 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 8b 5c 29 3c 03 dd 03 6c 29 24 57}  //weight: 1, accuracy: High
        $x_1_3 = {8b f4 56 68 ?? ?? ?? ?? 57 ff d5 ad 85 c0 74 ee}  //weight: 1, accuracy: Low
        $x_2_4 = {ff d3 ad 3d ?? ?? ?? ?? 75 dd ff e6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_R_2147728190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!R"
        threat_id = "2147728190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 76 30 8b 76 0c 8b 76 1c 56 ?? ?? ?? ?? 5f 8b 6f 08 ff 37 8b 5d 3c 8b 5c 1d 78 01 eb 8b 4b 18 67 e3 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {32 17 66 c1 ca 01 ae 75 f7 49 66 39 f2 74 08 67 e3 cb}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 fa da f0 74 1b 66 81 fa 69 27 74 20 6a 32 68 6f 6c 65 33 54 ff d7}  //weight: 1, accuracy: High
        $x_1_4 = {68 6e 04 22 d4 68 a1 ec ef 99 68 b9 72 92 49 68 74 df 44 6c}  //weight: 1, accuracy: High
        $x_1_5 = {68 4f 79 73 96 68 9e e3 01 c0}  //weight: 1, accuracy: High
        $x_1_6 = {68 91 33 d2 11 68 77 93 74 96}  //weight: 1, accuracy: High
        $x_1_7 = {89 e3 56 54 50 6a 17 56 53 ff d7}  //weight: 1, accuracy: High
        $x_2_8 = "hog Uhop th!dnh" ascii //weight: 2
        $x_1_9 = {ac 66 50 3c 55 75 f9 89 e1 31 c0 50 50 51 53 8b 13 8b 4a 50 ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_J_2147729421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.gen!J"
        threat_id = "2147729421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {b8 04 02 00 00 29 c4 48 48 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {50 50 50 6a 06 40 50 6a 17 68 ea 0f df e0}  //weight: 1, accuracy: High
        $x_1_4 = {ff d5 89 c7 6a 1c e8 1c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 68 99 a5 74 61 ff d5}  //weight: 1, accuracy: High
        $x_1_6 = {6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5}  //weight: 1, accuracy: High
        $x_1_7 = {68 00 10 00 00 56 6a 00 68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_O_2147729928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.O"
        threat_id = "2147729928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 68 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {68 64 6e 73 61 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {50 68 6a c9 9c c9 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {68 f4 00 8e cc ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_O_2147729928_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.O"
        threat_id = "2147729928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 c6 96 87 52 89 44 ?? ?? e8 [0-10] c7 04 24 4c 77 26 07}  //weight: 1, accuracy: Low
        $x_1_2 = {77 73 32 5f c7 44 24 ?? 33 32 2e 64 [0-6] c6 44 24 ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d0 83 ec 04 c7 04 24 99 a5 74 61 e8}  //weight: 1, accuracy: High
        $x_1_4 = {c7 04 24 52 f3 e2 51 e8 ?? ?? ?? ?? c7 04 24 5f 78 54 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_O_2147729928_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.O"
        threat_id = "2147729928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 52 60 [0-4] 48 8b 52 18 [0-4] 48 8b 52 20}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 41 59 68 00 10 00 00 41 58 48 89 f2 48 31 c9 41 ba 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 48 89 f9 41 ba ad 9e 5f bb ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 59 49 c7 c2 f0 b5 a2 56 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = "\\\\.\\pipe\\" ascii //weight: 1
        $x_1_6 = {6a 00 59 bb e0 1d 2a 0a 41 89 da ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Meterpreter_O_2147729928_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.O"
        threat_id = "2147729928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 8b 80 88 00 00 00 48 85 c0 74}  //weight: 1, accuracy: High
        $x_1_2 = {ff e0 58 41 59 5a 48 8b 12 e9 ?? ?? ?? ?? 5d 48 ba 01 00 00 00 00 00 00 00 48 8d 8d ?? ?? 00 00 41 ba 31 8b 6f 87 ff d5 bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_O_2147729928_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.O"
        threat_id = "2147729928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3}  //weight: 1, accuracy: High
        $x_1_2 = {ff e0 5f 5f 5a 8b 12 eb ?? 5d 6a 01 8d 85 ?? 00 00 00 50 68 31 8b 6f 87 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 47 13 72 6f 6a 00 53 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {ff e0 5f 5f 5a 8b 12 eb 8d 5d 8d 85 ?? 00 00 00 50 68 4c 77 26 07 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Meterpreter_2147750887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter!MSR"
        threat_id = "2147750887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DownLoadString('http://t.amy'+'nx.com/7p.php?0.8*usb_lnk*%username%*%computername%*'+[Environment]::OSVersion.version.Major);bpu ('http://t.amy'+'nx.co" ascii //weight: 2
        $x_1_2 = "mshta vbscript:createobject(\"wscript.shell\").run(\"cmd /c powershell -w hidden IE" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meterpreter_RPX_2147844724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.RPX!MTB"
        threat_id = "2147844724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f9 89 de 8a 06 30 07 47 66 81 3f ?? ?? 74 08 46 80 3e ?? 75 ee eb ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_RPX_2147844724_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.RPX!MTB"
        threat_id = "2147844724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 8a 9c 3c d8 01 00 00 99 f7 fe 0f b6 cb 0f be 84 14 c4 01 00 00 03 44 24 0c 03 c8 0f b6 c9 89 4c 24 0c 8a 84 0c d8 01 00 00 88 84 3c d8 01 00 00 47 88 9c 0c d8 01 00 00 81 ff 00 01 00 00 7c be}  //weight: 1, accuracy: High
        $x_1_2 = "49.232.192.98" ascii //weight: 1
        $x_1_3 = "guoguo" ascii //weight: 1
        $x_1_4 = "Reverse_TCP_RC4" ascii //weight: 1
        $x_1_5 = "viper.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_CRXM_2147850221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.CRXM!MTB"
        threat_id = "2147850221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc e8 8f 00 00 00 60 31 d2 64 8b 52 30 89 e5 8b 52 0c 8b 52 14 0f b7 4a 26 8b 72 28 31}  //weight: 1, accuracy: High
        $x_1_2 = {10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4c 01 d0 8b 58 20 01 d3 50 8b 48 18 85 c9}  //weight: 1, accuracy: High
        $x_1_3 = {f8 3b 7d 24 75 e0 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_RPZ_2147897077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.RPZ!MTB"
        threat_id = "2147897077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_IG_2147911679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.IG!MTB"
        threat_id = "2147911679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 db 8a 94 1d ?? ?? ?? ?? 88 94 05 ?? ?? ?? ?? 89 fa 88 94 1d ?? ?? ?? ?? 02 94 05 ?? ?? ?? ?? 0f b6 d2 8a 94 15 ?? ?? ?? ?? 30 11 41 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Meterpreter_SZ_2147921608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meterpreter.SZ!MTB"
        threat_id = "2147921608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Calling command_exec" ascii //weight: 2
        $x_2_2 = "Calling decode_payload" ascii //weight: 2
        $x_2_3 = "exec_shellcode64 called" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Refpron_2147609344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refpron"
        threat_id = "2147609344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d e8 66 ba 88 2e b8 ?? ?? 00 10 e8 ?? ?? ff ff 8b 4d e8 8b 15 ?? ?? 00 10 8b 12 8d 45 ec e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 fc 8d 4d f8 66 ba 88 2e b8 ?? ?? 00 10 e8 ?? ?? ff ff 33 c0 55 68}  //weight: 1, accuracy: Low
        $x_2_3 = "My_M_i_niT_C_PC_lient" ascii //weight: 2
        $x_2_4 = "e_r_r_" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Refpron_A_2147610838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refpron.gen!A"
        threat_id = "2147610838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 08 32 d1 88 54 28 ff 8b 06 0f b6 44 28 ff 66 03 f8 66 69 c7 6d ce 66 05 bf 58 8b f8 43 66 ff 0c 24 75}  //weight: 1, accuracy: High
        $x_1_2 = {74 20 8b 75 ec 68 (0d|0c) ba db 00 56 e8 ?? ?? ff ff 3d 02 01 00 00 75 09 50 56 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 88 13 00 00 e8 ?? ?? ff ff 05 e8 03 00 00 50 e8 ?? ?? ff ff e8 ?? ?? ff ff 84 c0 74 0c 68 11 27 00 00 e8 ?? ?? ff ff eb eb e8}  //weight: 1, accuracy: Low
        $x_1_4 = "My_M_i_niT_C_PC_lient" ascii //weight: 1
        $x_1_5 = {0f 00 00 00 50 6c 41 64 6b 4d 33 64 44 67 6e 76 56 2b 4c 00}  //weight: 1, accuracy: High
        $x_1_6 = {0e 00 00 00 64 39 62 54 6a 4e 77 6f 36 63 76 4b 59 41 00}  //weight: 1, accuracy: High
        $x_1_7 = {1c 00 00 00 53 65 74 20 20 20 46 69 6c 65 20 20 20 54 69 6d 65 20 20 20 45 72 72 6f 72 21 21 21 00 00 00 00 ff ff ff ff 23 00 00 00 53 65 74 20 20 20 46 69 6c 65 20 20 20 54 69 6d 65 20 20 20 53 75 63 63 65 73 73 66 75 6c 6c 79 21 21 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Refpron_B_2147612328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refpron.gen!B"
        threat_id = "2147612328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 05 bf 58 0b 00 [0-6] 66 69 ?? 6d ce}  //weight: 1, accuracy: Low
        $x_2_2 = {c7 40 0c c8 20 00 00 ba c0 d4 01 00 8b 45 ?? e8}  //weight: 2, accuracy: Low
        $x_1_3 = {68 0d ba db 00 8b 45 f0 50 e8 ?? ?? ff ff 89 45 ?? 81 7d ?? 02 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_4 = {68 0d ba db 00 56 e8 ?? ?? ff ff 3d 02 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_5 = {63 00 00 00 02 00 00 00 5c 00 00 00 02 00 00 00 50 00 00 00 02 00 00 00 68 00 00 00 02 00 00 00 79 00 00 00 02 00 00 00 73 00 00 00 02 00 00 00 61 00 00 00 02 00 00 00 6c 00 00 00 02 00 00 00 4d 00 00 00 02 00 00 00 6d 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 53 65 74 20 04 00 46 69 6c 65 20 04 00 54 69 6d 65 20 04 00 53 75 63 63 65 73 73 66 75 6c 6c 79 21 21 21 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Refpron_C_2147621627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refpron.gen!C"
        threat_id = "2147621627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 a1 ?? ?? ?? ?? c6 00 01 [0-64] 66 ba ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 55 ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 8d 4d ?? 66 ba ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 55 ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 8d 4d ?? 66 ba ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 55 ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ff 8d 4d ?? 66 ba ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 eb 08 32 [0-64] 66 03 ?? ?? 66 69 c0 6d ce 66 05 bf 58 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Refpron_E_2147622758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refpron.E"
        threat_id = "2147622758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {66 69 c0 6d ce 66 05 bf 58 66 89 45 f0}  //weight: 100, accuracy: High
        $x_10_2 = "NeedSendProcessList" ascii //weight: 10
        $x_10_3 = "DisableScriptDebuggerIE" ascii //weight: 10
        $x_10_4 = "74.54.201.210" ascii //weight: 10
        $x_5_5 = "URLDownloadToFileA" ascii //weight: 5
        $x_5_6 = "DeleteUrlCacheEntry" ascii //weight: 5
        $x_5_7 = "SOFTWARE\\Microsoft\\WBEM" ascii //weight: 5
        $x_5_8 = "txtfile\\shell\\open\\command" ascii //weight: 5
        $x_5_9 = "rtl60.bpl" ascii //weight: 5
        $x_5_10 = "rtl60.bin" ascii //weight: 5
        $x_1_11 = "discover.exe" ascii //weight: 1
        $x_1_12 = "msrstart.exe" ascii //weight: 1
        $x_1_13 = "nxtepad.exe" ascii //weight: 1
        $x_1_14 = {63 3a 5c 74 65 6d 70 5c 6d 74 61 [0-8] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_15 = "dictsd32.sys" ascii //weight: 1
        $x_1_16 = "comsa32.sys" ascii //weight: 1
        $x_1_17 = "FInstall.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 6 of ($x_5_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 4 of ($x_5_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Refpron_F_2147627139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refpron.F"
        threat_id = "2147627139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d ba db 00 8b 45 f0 50 a1 ?? ?? ?? ?? 8b 00 ff d0 89 45 ec 81 7d ec 02 01 00 00 c6 45 fb 01 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 e4 6d ce 00 00 [0-32] 66 05 bf 58}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 32 00 00 00 e8 ?? ?? ?? ?? 83 c0 0a 89 45 ?? 69 45 ?? e8 03 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Refpron_H_2147631421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refpron.H"
        threat_id = "2147631421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d ce 8b c0 bf 58 8b c0}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 3d 02 01 00 00 75 b3 01 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Refpron_D_2147634433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refpron.gen!D"
        threat_id = "2147634433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 5b 75 ed b8 61 00 00 00 8b d0 80 ea 47 33 c9 8a c8 88 54 0d 00 40 83 f8 7b 75 ed}  //weight: 1, accuracy: High
        $x_1_2 = {b9 b8 0b 00 00 33 d2 b8 02 00 00 00 e8 ?? ?? ff ff 85 c0 74 53}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 d6 8d 44 10 ff 50 8b c7 8b d5 32 c2 5a 88 02 0f b7 c6 8b 14 24 0f b6 7c 02 ff 0f b7 c3 03 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


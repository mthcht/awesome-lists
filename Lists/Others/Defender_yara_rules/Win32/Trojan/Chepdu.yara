rule Trojan_Win32_Chepdu_A_2147609764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.A"
        threat_id = "2147609764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ssid=%s&url=%s&id=%s&idfeed=%i&efkwd=%s" ascii //weight: 1
        $x_1_2 = "sid=%s&url=%s&id=%s&key=%s&idfeed=%i" ascii //weight: 1
        $x_1_3 = {52 00 65 00 66 00 65 00 72 00 65 00 72 00 3a 00 20 00 25 00 68 00 73 00 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 70 65 63 68 75 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chepdu_B_2147609921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.B"
        threat_id = "2147609921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 5c 4b 42 25 69 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 69 64 6b 65 79 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 65 66 6b 77 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 00 65 00 66 00 65 00 72 00 65 00 72 00 3a 00 20 00 25 00 68 00 73 00 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 70 65 63 68 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 75 73 65 72 69 6e 69 74 7c 25 73 7c 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_8 = {25 32 36 00 25 32 36 70 3d [0-4] 25 33 66 70 3d 00}  //weight: 1, accuracy: Low
        $x_1_9 = {7c 44 4c 3a 00}  //weight: 1, accuracy: High
        $x_1_10 = {25 32 36 70 3d 00}  //weight: 1, accuracy: High
        $x_1_11 = {4d 00 61 00 6e 00 79 00 42 00 6f 00 78 00 2e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_3_12 = {99 b9 00 7d 00 00 f7 f9 81 c2 a8 61 00 00 89 95 ?? ?? ?? ff ff 15 ?? ?? ?? ?? 6a 00 6a 26}  //weight: 3, accuracy: Low
        $x_2_13 = {85 c0 74 1d 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 74 07 33 c0 e9 ?? ?? 00 00 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Chepdu_C_2147610975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.C"
        threat_id = "2147610975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 10, accuracy: High
        $x_10_2 = "%ssid=%s&url=%s&id=" ascii //weight: 10
        $x_2_3 = {58 4d 4c 32 76 74 69 64 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e}  //weight: 2, accuracy: High
        $x_2_4 = "= s 'XMLLIB.XMLDP'" ascii //weight: 2
        $x_1_5 = {72 65 67 73 76 72 33 32 2e 65 78 65 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = "%s\\KB%i.exe" ascii //weight: 1
        $x_1_7 = "%suserinit|%s|%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Chepdu_D_2147616269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.D"
        threat_id = "2147616269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 10, accuracy: High
        $x_10_2 = {00 58 4d 4c 32}  //weight: 10, accuracy: High
        $x_2_3 = "%suserinit|%s|%s" ascii //weight: 2
        $x_2_4 = {72 65 67 73 76 72 33 32 2e 65 78 65 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_5 = "CoInternetCompareUrl" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA'" ascii //weight: 1
        $x_1_7 = {71 3d 00 73 65 61 72 63 68 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Chepdu_G_2147618527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.G"
        threat_id = "2147618527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" ascii //weight: 1
        $x_1_2 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 00 78 6d 6c 77 69 6e 64 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chepdu_H_2147619212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.H"
        threat_id = "2147619212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00}  //weight: 1, accuracy: High
        $x_1_2 = "c:/windows/system32/Drivers/Etc/hosts" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_4 = "%66%69%6E%64%65%72%2E%63%63" ascii //weight: 1
        $x_1_5 = "xxx-gate.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chepdu_P_2147625860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.P"
        threat_id = "2147625860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 43 4f 4e 46 49 47 [0-7] 48 4b 45 59 5f 44 59 4e 5f 44 41 54 41 [0-7] 48 4b 45 59 5f 50 45 52 46 4f 52 4d 41 4e 43 45 5f 44 41 54 41 [0-7] 48 4b 45 59 5f 55 53 45 52 53 [0-7] 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 [0-7] 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 [0-7] 48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 [0-7] 48 4b 43 43 [0-7] 48 4b 44 44 [0-7] 48 4b 50 44 [0-7] 48 4b 55 [0-7] 48 4b 4c 4d [0-7] 48 4b 43 55 [0-7] 48 4b 43 52}  //weight: 2, accuracy: Low
        $x_2_2 = {0b ca 88 8d ?? ?? ff ff 80 00 0f be 8d ?? ?? ff ff [0-80] 0f be 95 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = {25 00 00 00 80 79 05 48 83 c8 ff 40 3d ?? ?? 00 00 75 06}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 01 00 00 00 83 e0 01 85 c0 74}  //weight: 1, accuracy: High
        $x_1_5 = {81 38 63 73 6d e0 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Chepdu_V_2147648816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.V"
        threat_id = "2147648816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 2e 74 6c 62 00 00 00 00 5c 49 6d 70 6c 65 6d 65 6e 74 65 64 20 43 61 74 65 67 6f 72 69 65 73}  //weight: 1, accuracy: High
        $x_1_2 = {08 38 da f1 49 44 4f 4d 50 65 65 6b}  //weight: 1, accuracy: High
        $x_1_3 = {33 45 04 89 45 fc 83 7d 08 00 74 45 68 00 01 00 00 8d 85 f8 fe ff ff 50 6a 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chepdu_W_2147648957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.W"
        threat_id = "2147648957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 6d 8b 04 [0-5] 68 80 01 00 00 50 6a 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {be 80 d1 f0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chepdu_X_2147651525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.X"
        threat_id = "2147651525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 82 00 00 76 4e 83 fe 00 77 ?? 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chepdu_Y_2147655714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepdu.Y"
        threat_id = "2147655714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 2e 74 6c 62 00 00 00 00 5c 49 6d 70 6c 65 6d 65 6e 74 65 64 20 43 61 74 65 67 6f 72 69 65 73}  //weight: 1, accuracy: High
        $x_1_2 = {0a 44 4f 4d 50 65 65 6b 57 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 45 04 89 45 fc 83 7d 08 00 74 45 68 00 01 00 00 8d 85 f8 fe ff ff 50 6a 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


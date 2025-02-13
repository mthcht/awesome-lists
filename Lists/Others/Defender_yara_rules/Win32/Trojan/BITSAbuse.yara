rule Trojan_Win32_BITSAbuse_A_2147728729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.A"
        threat_id = "2147728729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1110"
        strings_accuracy = "Low"
    strings:
        $n_1000_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 [0-64] 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00}  //weight: -1000, accuracy: Low
        $x_100_2 = {63 00 6d 00 64 00 [0-32] 2f 00 63 00}  //weight: 100, accuracy: Low
        $x_10_3 = {26 00 62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00}  //weight: 10, accuracy: Low
        $x_10_4 = {26 00 20 00 62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00}  //weight: 10, accuracy: Low
        $x_1000_5 = {68 00 74 00 74 00 70 00 [0-192] 20 00 [0-64] 2e 00 65 00 78 00 65 00 [0-32] 26 00 [0-64] 2e 00 65 00 78 00 65 00}  //weight: 1000, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_1000_*) and 1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BITSAbuse_B_2147728730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.B"
        threat_id = "2147728730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 [0-64] 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00}  //weight: 10, accuracy: Low
        $x_10_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 [0-240] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 61 00 64 00 64 00 66 00 69 00 6c 00 65 00 [0-240] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_4 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 73 00 65 00 74 00 6e 00 6f 00 74 00 69 00 66 00 79 00 63 00 6d 00 64 00 6c 00 69 00 6e 00 65 00 [0-240] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_5 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 73 00 65 00 74 00 6e 00 6f 00 74 00 69 00 66 00 79 00 63 00 6d 00 64 00 6c 00 69 00 6e 00 65 00 [0-240] 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_6 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 73 00 65 00 74 00 6e 00 6f 00 74 00 69 00 66 00 79 00 63 00 6d 00 64 00 6c 00 69 00 6e 00 65 00 [0-240] 62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00}  //weight: 10, accuracy: Low
        $x_10_7 = {63 00 6f 00 70 00 79 00 20 00 2d 40 40 01 26 62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 2d 40 40 01 26 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BITSAbuse_C_2147728731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.C"
        threat_id = "2147728731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6d 00 64 00 [0-32] 2f 00 63 00}  //weight: 10, accuracy: Low
        $x_10_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00}  //weight: 10, accuracy: Low
        $x_10_3 = {68 00 74 00 74 00 70 00 [0-240] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_1_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-240] 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 00 74 00 61 00 72 00 74 00 [0-240] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BITSAbuse_AS_2147729613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.AS"
        threat_id = "2147729613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 61 00 64 00 64 00 66 00 69 00 6c 00 65 00 20 00 2d 40 40 01 20 20 00 5c 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 5c 00 [0-2] 24 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 61 00 64 00 64 00 66 00 69 00 6c 00 65 00 20 00 2d 40 40 01 20 20 00 5c 00 5c 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00 [0-2] 24 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 61 00 64 00 64 00 66 00 69 00 6c 00 65 00 20 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BITSAbuse_BS_2147729614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.BS"
        threat_id = "2147729614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 52 00 65 00 6d 00 6f 00 74 00 65 00 50 00 72 00 65 00 66 00 69 00 78 00 20 00 2d 40 40 01 20 20 00 2d 40 40 01 20 20 00 5c 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 52 00 65 00 6d 00 6f 00 74 00 65 00 50 00 72 00 65 00 66 00 69 00 78 00 20 00 2d 40 40 01 20 20 00 2d 40 40 01 20 20 00 5c 00 5c 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 52 00 65 00 6d 00 6f 00 74 00 65 00 50 00 72 00 65 00 66 00 69 00 78 00 20 00 2d 40 40 01 20 20 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BITSAbuse_CS_2147729615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.CS"
        threat_id = "2147729615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 53 00 65 00 74 00 4e 00 6f 00 74 00 69 00 66 00 79 00 43 00 6d 00 64 00 4c 00 69 00 6e 00 65 00 20 00 2d 40 40 01 20 20 00 2d 40 40 01 20 20 00 [0-64] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 4, accuracy: Low
        $x_4_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 53 00 65 00 74 00 4e 00 6f 00 74 00 69 00 66 00 79 00 43 00 6d 00 64 00 4c 00 69 00 6e 00 65 00 20 00 2d 40 40 01 20 20 00 2d 40 40 01 20 20 00 [0-64] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BITSAbuse_D_2147731551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.D"
        threat_id = "2147731551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 [0-32] 2f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = "certutil -decode" wide //weight: 1
        $x_1_4 = {73 00 74 00 61 00 72 00 74 00 [0-240] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BITSAbuse_E_2147731552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.E"
        threat_id = "2147731552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 [0-32] 2f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 72 00 65 00 73 00 65 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 61 00 64 00 64 00 66 00 69 00 6c 00 65 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 73 00 65 00 74 00 6e 00 6f 00 74 00 69 00 66 00 79 00 66 00 6c 00 61 00 67 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 73 00 65 00 74 00 6e 00 6f 00 74 00 69 00 66 00 79 00 63 00 6d 00 64 00 6c 00 69 00 6e 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 72 00 65 00 73 00 75 00 6d 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BITSAbuse_H_2147778891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.H"
        threat_id = "2147778891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-32] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 [0-64] 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00}  //weight: 10, accuracy: Low
        $x_10_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-32] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00}  //weight: 10, accuracy: Low
        $x_10_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-32] 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 10, accuracy: Low
        $x_10_4 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-32] 2f 00 61 00 64 00 64 00 66 00 69 00 6c 00 65 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BITSAbuse_TJ_2147797966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.TJ!se"
        threat_id = "2147797966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        info = "se: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 2d 40 40 01 20 20 00 5c 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 5c 00 [0-2] 24 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 2d 40 40 01 20 20 00 5c 00 5c 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00 [0-2] 24 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BITSAbuse_DJ_2147797967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.DJ!se"
        threat_id = "2147797967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        info = "se: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 2d 40 40 01 20 20 00 5c 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 5c 00 [0-2] 24 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 2d 40 40 01 20 20 00 5c 00 5c 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00 [0-2] 24 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2d 08 08 01 20 20 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00 2d 40 40 01 20 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BITSAbuse_PJ_2147797968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.PJ!se"
        threat_id = "2147797968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        info = "se: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 00 74 00 61 00 72 00 74 00 2d 00 62 00 69 00 74 00 73 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2d 08 08 01 20 20 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 5c 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 5c 00 [0-2] 24 00 5c 00 2d 40 40 01 20 20 00 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_2 = {73 00 74 00 61 00 72 00 74 00 2d 00 62 00 69 00 74 00 73 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2d 08 08 01 20 20 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 5c 00 5c 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00 [0-2] 24 00 5c 00 2d 40 40 01 20 20 00 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
        $x_4_3 = {73 00 74 00 61 00 72 00 74 00 2d 00 62 00 69 00 74 00 73 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2d 08 08 01 20 20 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 [0-2] 3a 00 5c 00 2d 40 40 01 20 20 00 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 20 00 [0-2] 3a 00 5c 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


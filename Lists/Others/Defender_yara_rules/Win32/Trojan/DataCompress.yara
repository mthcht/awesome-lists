rule Trojan_Win32_DataCompress_V_2147768884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataCompress.V"
        threat_id = "2147768884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataCompress"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 2d 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 70 00 6f 00 6c 00 69 00 63 00 79 00 [0-3] 5c 00 62 00 79 00 70 00 61 00 73 00 73 00 [0-2] 2d 00 63 00 [0-80] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-2] 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2d 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 [0-2] 2d 00 6e 00 61 00 6d 00 65 00 [0-2] 5c 00 37 00 7a 00 69 00 70 00 34 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-2] 2d 00 76 00 65 00 72 00 62 00 6f 00 73 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2d 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 [0-2] 2d 00 6e 00 61 00 6d 00 65 00 [0-2] 37 00 7a 00 69 00 70 00 34 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-2] 2d 00 76 00 65 00 72 00 62 00 6f 00 73 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 2d 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 70 00 6f 00 6c 00 69 00 63 00 79 00 [0-3] 5c 00 62 00 79 00 70 00 61 00 73 00 73 00 [0-2] 2d 00 63 00 [0-80] 5c 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 2d 00 37 00 7a 00 69 00 70 00 [0-2] 2d 00 70 00 61 00 74 00 68 00 [0-2] 24 00 65 00 6e 00 76 00 3a 00 [0-16] 2d 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 2d 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 [0-16] 2d 00 70 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_5 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 2d 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 [0-16] 2d 00 6c 00 69 00 74 00 65 00 72 00 61 00 6c 00 70 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_6 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 2d 00 37 00 7a 00 69 00 70 00 [0-16] 2d 00 70 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_7 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 2d 00 37 00 7a 00 69 00 70 00 [0-16] 2d 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-2] 61 00 64 00 64 00 2d 00 74 00 79 00 70 00 65 00 78 00 39 00 30 00 02 02 2d 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 6e 00 61 00 6d 00 65 00 [0-2] 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 69 00 6f 00 2e 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 2e 00 66 00 69 00 6c 00 65 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_9 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-2] 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 63 00 69 00 6d 00 6d 00 65 00 74 00 68 00 6f 00 64 00 [0-2] 2d 00 71 00 75 00 65 00 72 00 79 00 [0-2] 24 00 71 00 75 00 65 00 72 00 79 00 [0-2] 2d 00 6d 00 65 00 74 00 68 00 6f 00 64 00 6e 00 61 00 6d 00 65 00 [0-2] 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_10 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-2] 67 00 65 00 74 00 2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-2] 2d 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 [0-5] 5c 00 37 00 7a 00 69 00 70 00 34 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_DataCompress_VA_2147768885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataCompress.VA"
        threat_id = "2147768885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataCompress"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {37 00 7a 00 69 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DataCompress_VB_2147768886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataCompress.VB"
        threat_id = "2147768886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataCompress"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 61 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DataCompress_VC_2147768887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataCompress.VC"
        threat_id = "2147768887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataCompress"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 00 69 00 70 00 2e 00 65 00 78 00 65 00 [0-16] 2d 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {7a 00 69 00 70 00 2e 00 65 00 78 00 65 00 [0-16] 2d 00 63 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 1, accuracy: Low
        $n_10_3 = {5c 00 74 00 68 00 6f 00 6d 00 73 00 6f 00 6e 00 72 00 65 00 75 00 74 00 65 00 72 00 73 00 [0-60] 5c 00 73 00 69 00 6e 00 67 00 6c 00 65 00 77 00 69 00 6e 00 64 00 6f 00 77 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_DataCompress_A_2147769393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataCompress.A!7zip"
        threat_id = "2147769393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataCompress"
        severity = "Critical"
        info = "7zip: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7z.exe" wide //weight: 1
        $x_1_2 = " 7z " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_DataCompress_B_2147769394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataCompress.B!rar"
        threat_id = "2147769394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataCompress"
        severity = "Critical"
        info = "rar: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rar " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DataCompress_B_2147769879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataCompress.B!7zip"
        threat_id = "2147769879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataCompress"
        severity = "Critical"
        info = "7zip: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7za.exe" wide //weight: 1
        $x_1_2 = " 7za " wide //weight: 1
        $n_10_3 = "--help" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}


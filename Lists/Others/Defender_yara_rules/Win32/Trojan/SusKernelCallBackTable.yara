rule Trojan_Win32_SusKernelCallBackTable_MK_2147945824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusKernelCallBackTable.MK"
        threat_id = "2147945824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusKernelCallBackTable"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 65 72 6e 65 6c 43 61 6c 6c 62 61 63 6b 54 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 6e 64 4d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_8 = {5f 5f 66 6e 43 4f 50 59 44 41 54 41 00}  //weight: 1, accuracy: High
        $x_1_9 = {57 4d 5f 43 4f 50 59 44 41 54 41 00}  //weight: 1, accuracy: High
        $n_1_10 = "aa06e39e-7876-4ba3-beee-42bd80ff362e" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusKernelCallBackTable_MK_2147945824_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusKernelCallBackTable.MK"
        threat_id = "2147945824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusKernelCallBackTable"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 65 72 6e 65 6c 43 61 6c 6c 62 61 63 6b 54 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 6e 64 4d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_8 = {5f 5f 66 6e 43 4f 50 59 44 41 54 41 00}  //weight: 1, accuracy: High
        $x_1_9 = {57 4d 5f 43 4f 50 59 44 41 54 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusKernelCallBackTable_AM_2147946867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusKernelCallBackTable.AM"
        threat_id = "2147946867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusKernelCallBackTable"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 65 72 6e 65 6c 43 61 6c 6c 62 61 63 6b 54 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 6e 64 4d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 6e 43 4f 50 59 44 41 54 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 73 69 6e 66 6f 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $n_1_5 = "aa06e36e-7876-4ba3-beee-42bd80ff362m" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusKernelCallBackTable_AM_2147946867_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusKernelCallBackTable.AM"
        threat_id = "2147946867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusKernelCallBackTable"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 65 72 6e 65 6c 43 61 6c 6c 62 61 63 6b 54 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 6e 64 4d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 6e 43 4f 50 59 44 41 54 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 73 69 6e 66 6f 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


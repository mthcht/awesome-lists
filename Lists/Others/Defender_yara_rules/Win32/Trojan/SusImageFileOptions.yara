rule Trojan_Win32_SusImageFileOptions_MK_2147946866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusImageFileOptions.MK"
        threat_id = "2147946866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusImageFileOptions"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 69 6d 61 67 65 20 66 69 6c 65 20 65 78 65 63 75 74 69 6f 6e 20 6f 70 74 69 6f 6e 73 5c 6d 61 67 6e 69 66 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 62 73 69 6d 75 6c 61 74 69 6f 6e 5f 73 62 5f 90 02 ff 5f 62 73 5f 90 02 ff 5f 67 72 65 65 6e 2e 65 78 65}  //weight: 1, accuracy: High
        $n_1_4 = "aa06e39e-7876-4ba3-beez-42bd80ff362f" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusImageFileOptions_MK_2147946866_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusImageFileOptions.MK"
        threat_id = "2147946866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusImageFileOptions"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 69 6d 61 67 65 20 66 69 6c 65 20 65 78 65 63 75 74 69 6f 6e 20 6f 70 74 69 6f 6e 73 5c 6d 61 67 6e 69 66 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 62 73 69 6d 75 6c 61 74 69 6f 6e 5f 73 62 5f 90 02 ff 5f 62 73 5f 90 02 ff 5f 67 72 65 65 6e 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


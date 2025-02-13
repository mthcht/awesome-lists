rule Trojan_Win32_Puzlice_A_2147626967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Puzlice.A"
        threat_id = "2147626967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Puzlice"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AFTERDOWNLOAD" wide //weight: 1
        $x_1_2 = "&Publicer=" wide //weight: 1
        $x_1_3 = "zh-cn,zh;q" wide //weight: 1
        $x_1_4 = "Win32_NetworkAdapterConfiguration" wide //weight: 1
        $x_1_5 = {3a 00 38 00 38 [0-6] 00 0e 00 00 00 2f 00 70 00 36 00 2e 00 61 00 73 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Puzlice_B_2147679578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Puzlice.B"
        threat_id = "2147679578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Puzlice"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1b 85 00 1b 86 00 2a 23 78 ff 1b 87 00 2a 23 74 ff 1b 88 00 2a fd b7 36 00 32 04 00 78 ff 74 ff}  //weight: 1, accuracy: High
        $x_1_2 = "Publicer=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Puzlice_C_2147696740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Puzlice.C"
        threat_id = "2147696740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Puzlice"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 6e 64 65 78 2e 70 68 70 3f 75 73 65 72 49 44 3d 30 26 70 61 73 73 77 6f 72 64 3d 6e 75 6c 6c 26 75 73 65 72 63 75 72 3d 30 26 61 3d 72 65 67 69 73 74 72 61 74 69 6f 6e 5f 6d 61 69 6e 26 73 65 6e 64 3d 31 26 26 00}  //weight: 10, accuracy: High
        $x_10_2 = {26 61 3d 70 61 79 5f 69 6e 70 6c 61 74 26 63 6f 6e 66 69 72 6d 3d 4f 4b 26 61 6d 6f 75 6e 74 3d 31 30 30 26 6e 65 77 5f 75 69 3d 26 26 00}  //weight: 10, accuracy: High
        $x_10_3 = {54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 49 4d 20 00}  //weight: 10, accuracy: High
        $x_1_4 = {41 6e 56 69 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 74 72 61 66 66 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 74 61 72 74 47 75 61 72 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {4e 65 74 4d 6f 6e 69 74 6f 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {55 53 42 47 75 61 72 64 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_MpTamperDisableFeatureWd_A_2147797846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperDisableFeatureWd.A"
        threat_id = "2147797846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperDisableFeatureWd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 00 6e 00 6c 00 69 00 6e 00 65 00 [0-16] 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 2d 00 66 00 65 00 61 00 74 00 75 00 72 00 65 00 [0-16] 66 00 65 00 61 00 74 00 75 00 72 00 65 00 6e 00 61 00 6d 00 65 00 3a 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MpTamperDisableFeatureWd_B_2147797847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperDisableFeatureWd.B"
        threat_id = "2147797847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperDisableFeatureWd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 66 00 65 00 61 00 74 00 75 00 72 00 65 00 [0-32] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 65 00 6d 00 6f 00 76 00 65 00 2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 66 00 65 00 61 00 74 00 75 00 72 00 65 00 [0-32] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_MpTamperDisableFeatureWd_B_2147797847_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperDisableFeatureWd.B"
        threat_id = "2147797847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperDisableFeatureWd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dism" wide //weight: 10
        $x_10_2 = "windows-defender" wide //weight: 10
        $n_10_3 = "windows-defender-applicationguard" wide //weight: -10
        $n_20_4 = "/image:" wide //weight: -20
        $x_1_5 = "/disable-feature" wide //weight: 1
        $x_1_6 = "/remove" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule TrojanSpy_Win32_SuspShadowAccess_A_2147815717_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SuspShadowAccess.A"
        threat_id = "2147815717"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowAccess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {63 00 6f 00 70 00 79 00 [0-16] 5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 6f 00 74 00 5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 68 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 76 00 6f 00 6c 00 75 00 6d 00 65 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00}  //weight: 3, accuracy: Low
        $x_2_2 = "\\ntds\\ntds.dit" wide //weight: 2
        $x_2_3 = "\\config\\sam" wide //weight: 2
        $x_2_4 = "\\config\\security" wide //weight: 2
        $x_2_5 = "\\config\\system" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_SuspShadowAccess_B_2147815718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SuspShadowAccess.B"
        threat_id = "2147815718"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspShadowAccess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {6e 00 74 00 64 00 73 00 75 00 74 00 69 00 6c 00 [0-32] 61 00 63 00 [0-80] 6e 00 74 00 64 00 73 00}  //weight: 30, accuracy: Low
        $x_30_2 = {64 00 73 00 64 00 62 00 75 00 74 00 69 00 6c 00 [0-32] 61 00 63 00 [0-80] 6e 00 74 00 64 00 73 00}  //weight: 30, accuracy: Low
        $x_1_3 = {20 00 69 00 66 00 6d 00 [0-32] 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 69 00 20 00 [0-32] 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = " snapshot " wide //weight: 1
        $x_1_6 = " sn " wide //weight: 1
        $n_10_7 = "\\_lds_backups" wide //weight: -10
        $n_10_8 = "\\ICS-NET" wide //weight: -10
        $n_10_9 = "IFMBackup" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_30_*))) or
            (all of ($x*))
        )
}


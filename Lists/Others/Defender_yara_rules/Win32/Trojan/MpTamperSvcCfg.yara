rule Trojan_Win32_MpTamperSvcCfg_A_2147777413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSvcCfg.A"
        threat_id = "2147777413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSvcCfg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\windows\\system32\\sc.exe" wide //weight: 5
        $x_5_2 = "sdset " wide //weight: 5
        $x_1_3 = "wdfilter " wide //weight: 1
        $x_1_4 = "mssecflt " wide //weight: 1
        $x_1_5 = "sgrmagent " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperSvcCfg_B_2147777464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSvcCfg.B"
        threat_id = "2147777464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSvcCfg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\windows\\system32\\sc.exe" wide //weight: 5
        $x_5_2 = "sdset " wide //weight: 5
        $x_1_3 = "windefend " wide //weight: 1
        $x_1_4 = "wdfilter " wide //weight: 1
        $x_1_5 = "sense " wide //weight: 1
        $x_1_6 = "mssecflt " wide //weight: 1
        $x_1_7 = "msmpsvc " wide //weight: 1
        $x_1_8 = "sgrmagent " wide //weight: 1
        $n_11_9 = {20 00 73 00 64 00 73 00 65 00 74 00 20 00 [0-8] 61 00 70 00 70 00 73 00 65 00 6e 00 73 00 65 00 20 00}  //weight: -11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperSvcCfg_B_2147777464_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSvcCfg.B"
        threat_id = "2147777464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSvcCfg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 73 00 64 00 73 00 65 00 74 00 20 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 20 00 44 00 3a 00 [0-8] 28 00 44 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 73 00 64 00 73 00 65 00 74 00 20 00 73 00 65 00 6e 00 73 00 65 00 20 00 44 00 3a 00 [0-8] 28 00 44 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 73 00 64 00 73 00 65 00 74 00 20 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 20 00 44 00 3a 00 [0-8] 28 00 [0-255] 29 00 28 00 44 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 73 00 64 00 73 00 65 00 74 00 20 00 73 00 65 00 6e 00 73 00 65 00 20 00 44 00 3a 00 [0-8] 28 00 [0-255] 29 00 28 00 44 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


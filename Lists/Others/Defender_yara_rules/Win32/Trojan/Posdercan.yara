rule Trojan_Win32_Posdercan_A_2147768690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Posdercan.A"
        threat_id = "2147768690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Posdercan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 00 73 00 68 00 74 00 6d 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_2_6 = "raw.githubusercontent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Posdercan_B_2147778583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Posdercan.B"
        threat_id = "2147778583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Posdercan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 77 00 73 00 68 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = "raw.githubusercontent" wide //weight: 2
        $n_5_4 = "sysmon" wide //weight: -5
        $n_5_5 = "compassmsp" wide //weight: -5
        $n_5_6 = "caltec" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


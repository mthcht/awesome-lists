rule Trojan_Win32_BITSAbusePer_J_2147796529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbusePer.J"
        threat_id = "2147796529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbusePer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-32] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00}  //weight: 5, accuracy: Low
        $x_5_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-32] 2f 00 61 00 64 00 64 00 66 00 69 00 6c 00 65 00}  //weight: 5, accuracy: Low
        $x_5_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-32] 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_BITSAbusePer_AJ_2147797965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbusePer.AJ!ps"
        threat_id = "2147797965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbusePer"
        severity = "Critical"
        info = "ps: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 00 74 00 61 00 72 00 74 00 2d 00 62 00 69 00 74 00 73 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 [0-10] 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 [0-128] 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_SafeModeRebootAbuse_2147905724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SafeModeRebootAbuse"
        threat_id = "2147905724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SafeModeRebootAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 [0-8] 20 00 2f 00 73 00 65 00 74 00 20 00 [0-64] 20 00 73 00 61 00 66 00 65 00 62 00 6f 00 6f 00 74 00}  //weight: 10, accuracy: Low
        $x_10_2 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 [0-8] 20 00 2d 00 73 00 65 00 74 00 20 00 [0-64] 20 00 73 00 61 00 66 00 65 00 62 00 6f 00 6f 00 74 00}  //weight: 10, accuracy: Low
        $x_10_3 = {62 00 6f 00 6f 00 74 00 63 00 66 00 67 00 [0-8] 20 00 2f 00 72 00 61 00 77 00 20 00 [0-64] 20 00 2f 00 73 00 61 00 66 00 65 00 62 00 6f 00 6f 00 74 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


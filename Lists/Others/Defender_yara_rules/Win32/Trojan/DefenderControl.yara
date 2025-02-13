rule Trojan_Win32_DefenderControl_A_2147765801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefenderControl.A"
        threat_id = "2147765801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderControl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 [0-32] 20 00 2f 00 53 00 59 00 53 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 [0-32] 20 00 2f 00 54 00 49 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


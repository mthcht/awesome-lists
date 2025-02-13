rule Trojan_Win32_Susws_A_2147901581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Susws.A"
        threat_id = "2147901581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Susws"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 [0-255] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-255] 2f 00 74 00 72 00 [0-255] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-255] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


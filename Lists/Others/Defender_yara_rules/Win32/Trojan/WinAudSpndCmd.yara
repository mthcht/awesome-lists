rule Trojan_Win32_WinAudSpndCmd_A_2147835080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinAudSpndCmd.A"
        threat_id = "2147835080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinAudSpndCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 00 73 00 73 00 75 00 73 00 70 00 65 00 6e 00 64 00 [0-15] 77 00 69 00 6e 00 61 00 75 00 64 00 69 00 74 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


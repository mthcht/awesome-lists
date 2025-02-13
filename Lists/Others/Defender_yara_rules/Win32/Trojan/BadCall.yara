rule Trojan_Win32_BadCall_A_2147749966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadCall.A"
        threat_id = "2147749966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadCall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "cmd.exe" wide //weight: 5
        $x_5_2 = {2f 00 73 00 20 00 2f 00 64 00 20 00 2f 00 63 00 [0-8] 63 00 61 00 6c 00 6c 00 20 00 25 00 [0-8] 3a 00 [0-16] 3d 00 25 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


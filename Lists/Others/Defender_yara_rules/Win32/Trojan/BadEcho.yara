rule Trojan_Win32_BadEcho_A_2147740301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadEcho.A"
        threat_id = "2147740301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadEcho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "cmd.exe" wide //weight: 5
        $x_5_2 = {2f 00 73 00 20 00 2f 00 64 00 20 00 2f 00 63 00 [0-8] 65 00 63 00 68 00 6f 00 20 00 25 00 [0-4] 3a 00 [0-16] 3d 00 25 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


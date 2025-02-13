rule PWS_Win32_Wedsnot_A_2147629609_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Wedsnot.A"
        threat_id = "2147629609"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Wedsnot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 6c 18 00 00 c7 05 a4 99 40 00 01 00 00 00 b8 64 00 00 00 3b 05 a4 99 40 00 7c 13 ff 35 a4 99 40 00 e8 79 1a 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


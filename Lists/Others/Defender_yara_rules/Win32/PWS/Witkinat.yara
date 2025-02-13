rule PWS_Win32_Witkinat_A_2147634330_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Witkinat.A"
        threat_id = "2147634330"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Witkinat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 60 ea 00 00 73 ?? 68 ff 7f 00 00 b9 ?? ?? ?? ?? 8d 85 00 80 fd ff ba ff ff 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 00 00 01 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 68 82 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 f3 7f fe ff 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


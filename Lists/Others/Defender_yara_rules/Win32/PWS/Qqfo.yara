rule PWS_Win32_Qqfo_A_2147621481_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Qqfo.A"
        threat_id = "2147621481"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Qqfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e1 03 50 68 ?? ?? 40 00 6a 65 f3 a4 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 0f 84 ?? ?? 00 00 68 f4 01 00 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 01 f3 a4 6a 00 ff 15 ?? ?? 40 00 85 db 8b f0 74 07 68 40 e2 01 00 ff d3 68 30 75 00 00 56 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 78 65 00 00 00 7a 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


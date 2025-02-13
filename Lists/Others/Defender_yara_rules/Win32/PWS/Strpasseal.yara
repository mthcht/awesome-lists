rule PWS_Win32_Strpasseal_E_2147647626_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Strpasseal.E"
        threat_id = "2147647626"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Strpasseal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3b 26 75 4f 8b 03 3d 26 6c 74 3b 75 06 c6 04 37 3c eb 0b 3d 26 67 74 3b}  //weight: 1, accuracy: High
        $x_1_2 = {80 30 19 40 80 38 00 75 f7}  //weight: 1, accuracy: High
        $x_1_3 = {bb 00 10 40 00 2b fb 8d 87 ?? ?? ?? ?? 89 45 ?? 56 68 00 00 00 08 6a 40 8d 45}  //weight: 1, accuracy: Low
        $x_1_4 = {be f3 4b 70 ed 33 db 68 6e 10 cf 9f 89 75 c8 c7 45 cc 8c f8 6f 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


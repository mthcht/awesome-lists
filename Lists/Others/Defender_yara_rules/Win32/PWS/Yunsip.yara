rule PWS_Win32_Yunsip_A_2147649429_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yunsip.A"
        threat_id = "2147649429"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yunsip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Print Screen]" wide //weight: 1
        $x_1_2 = {6e 00 37 00 5f 00 32 00 30 00 31 00 30 00 5f 00 25 00 64 00 12 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 57 00 69 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 00 38 00 5f 00 32 00 30 00 31 00 31 00 5f 00 25 00 64 00 12 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 57 00 69 00}  //weight: 1, accuracy: Low
        $x_1_4 = "<Enter>" wide //weight: 1
        $x_1_5 = "\\log.sc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


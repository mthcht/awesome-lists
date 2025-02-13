rule TrojanDownloader_Win32_Carrobat_A_2147730851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carrobat.A"
        threat_id = "2147730851"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carrobat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C: && cd %TEMP% && c^e^r^tutil -urlca^che -spl" ascii //weight: 1
        $x_1_2 = {69 74 20 2d 66 20 68 74 74 70 [0-2] 3a 2f 2f [0-32] 61 70 [0-1] 70 [0-2] 2e 63 6f 6d [0-16] 2f 31 2e 74 78 74 20 26 26 20 72 65 6e 20 31 2e 74 78 74 20 31 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_3 = "&& 1.bat && exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


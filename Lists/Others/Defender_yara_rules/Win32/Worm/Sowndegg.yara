rule Worm_Win32_Sowndegg_B_2147626472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sowndegg.B"
        threat_id = "2147626472"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sowndegg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\autorun.inf" wide //weight: 1
        $x_1_2 = "LocationURL" wide //weight: 1
        $x_1_3 = {52 65 61 64 54 58 54 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 58 54 46 69 6c 65 50 61 74 68 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 65 61 64 63 6f 64 65 62 72 31 00}  //weight: 1, accuracy: High
        $x_1_6 = "D:\\SD\\downloader\\downloadergg" ascii //weight: 1
        $x_1_7 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {43 00 6c 00 69 00 63 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {7c 00 7c 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {2f 00 2f 00 5c 00 5c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


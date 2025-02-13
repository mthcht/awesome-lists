rule BrowserModifier_Win32_Chnbho_123887_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Chnbho"
        threat_id = "123887"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Chnbho"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Language\\Chinese\\searchbar.ini" ascii //weight: 2
        $x_2_2 = {73 6f 67 6f 75 2e 63 6f 6d 2f 65 78 70 72 65 73 73 2f 73 71 2e 6a 73 70 3f 71 75 65 72 79 3d 00 73 6f 2e 71 71 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 71 71 73 65 61 72 63 68 00 00 26 63 68 61 6e 6e 65 6c 3d 74 62 68 5f 75 72 6c}  //weight: 2, accuracy: High
        $x_2_3 = {7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 78 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d 00 00 25 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_4 = "name.cnnic.net" ascii //weight: 1
        $x_1_5 = "www.baidu.com/baidu" ascii //weight: 1
        $x_1_6 = "3721.com/cns.dll" ascii //weight: 1
        $x_1_7 = "page.zhongsou.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


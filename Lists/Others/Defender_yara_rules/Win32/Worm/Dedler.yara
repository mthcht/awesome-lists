rule Worm_Win32_Dedler_AE_2147599985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dedler.AE"
        threat_id = "2147599985"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dedler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 24 00 53 56 8b 35 ?? ?? ?? ?? 57 6a 14 50 68 ?? ?? ?? ?? ff d6 8d 4c 24 20 68 ff 00 00 00 51 68 ?? ?? ?? ?? ff d6 83 c9 ff 8d 7c 24 0c 33 c0 8b 94 24 24 01 00 00 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03}  //weight: 1, accuracy: Low
        $x_1_2 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii //weight: 1
        $x_1_3 = "login.icq.com" ascii //weight: 1
        $x_1_4 = "%sauto.php?v=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


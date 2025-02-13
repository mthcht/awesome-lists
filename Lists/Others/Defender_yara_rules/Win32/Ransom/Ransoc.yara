rule Ransom_Win32_Ransoc_A_2147718318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ransoc.A"
        threat_id = "2147718318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ransoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 54 24 04 8b ca 83 e1 03 03 c9 b8 90 00 00 00 d3 f8 c1 ea 02 8d 0c 52 83 e0 03 03 c1}  //weight: 5, accuracy: High
        $x_5_2 = {8d 0c c5 05 00 00 00 b8 ab aa aa aa f7 e1 8b c2 c1 e8 02 83 7c 24 08 00 74 0a 83 c0 03 c1 e8 02 03 c0 03 c0}  //weight: 5, accuracy: High
        $x_5_3 = {c7 04 24 77 18 06 60 c7 44 24 04 76 03 05 79 c7 44 24 08 46 4e 7a 07 c7 44 24 0c 4b 4d 04 49 c7 44 24 10 78 47 4f 5a c7 44 24 14 33 48 5b 71 c7 44 24 18 54 4c 94 8d c7 44 24 1c 4a 01 51 64 66 c7 44 24 20 09 0a c6 44 24 22 00}  //weight: 5, accuracy: High
        $x_1_4 = "127.0.0.1:%u/splash?ctrl=%u&f=1&id=%s" ascii //weight: 1
        $x_1_5 = "ipinfo_io_geo" ascii //weight: 1
        $x_1_6 = "api.ipify.org" ascii //weight: 1
        $x_1_7 = "linkedin.com" ascii //weight: 1
        $x_1_8 = "%s\\shared.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}


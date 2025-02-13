rule Worm_Win32_Antinny_BM_2147621670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Antinny.BM"
        threat_id = "2147621670"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Antinny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\system653.exe" ascii //weight: 1
        $x_1_2 = {73 79 73 74 65 6d 36 35 33 00 00 00 ff ff ff ff 2e 00 00 00 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
        $x_1_3 = "c:\\LOG01\\explorer" ascii //weight: 1
        $x_1_4 = "Noderef.txt" ascii //weight: 1
        $x_1_5 = "Download.txt" ascii //weight: 1
        $x_1_6 = "Upfolder.txt" ascii //weight: 1
        $x_1_7 = "shirane" ascii //weight: 1
        $x_1_8 = {b8 84 59 46 00 e8 75 39 fa ff 84 c0 0f 85 3b 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Fractured_2147603116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fractured"
        threat_id = "2147603116"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fractured"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 00 00 00 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 5f 00 52 00 61 00 77 00 00 00 00 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 00 00 00 00 7b 43 46 42 46 41 45 30 30 2d 31 37 41 36 2d 31 31 44 30 2d 39 39 43 42 2d 30 30 43 30 34 46 44 36 34 34 39 37 7d 00 00 7b 46 30 38 35 35 35 42 30 2d 39 43 43 33 2d 31 31 44 32 2d 41 41 38 45 2d 30 30 30 30 30 30 30 30 30 30 30 30 7d 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 55 52 4c 53 65 61 72 63 68 48 6f 6f 6b 73 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 6c 20 3d 20 73 20 27 42 6f 74 68 27 0d 0a 09 09 09 7d 0d 0a 09 09 09 27 54 79 70 65 4c 69 62 27 20 3d 20 73 20 27 7b 46 30 38 35 35 35 41 2d 30 30 30 30 30 30 30 30 30 30 30 30 7d 27 0d 00 0a 09 09 7d 0d 0a 09 7d 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\URLSearchHooks" ascii //weight: 1
        $x_1_4 = "ietool.dll" ascii //weight: 1
        $x_2_5 = "server.597update.com" ascii //weight: 2
        $x_2_6 = "www2.597update.com" ascii //weight: 2
        $x_1_7 = "IEToolPro" ascii //weight: 1
        $x_1_8 = "HotToolbar" wide //weight: 1
        $x_1_9 = {54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 33 00 32 00 00 00 48 00 6f 00 74 00 54 00 6f 00 6f 00 6c 00 62 00 61 00 72}  //weight: 1, accuracy: High
        $x_2_10 = {53 65 61 72 63 68 48 6f 6f 6b 2e 55 52 4c 53 65 61 72 63 68 48 6f 6f 6b 2e 31 20 3d 20 73 20 27 55 52 4c 53 65 61 72 63 68 48 6f 6f 6b 20 43 6c 61 73 73 27 0d 0a 09 7b 0d 0a 09 09 43 4c 53 49 44 20 3d 20 73 20 27 7b 43 35 30 36 37 46 35 39 2d 39 44 30 44 2d 31 31 44 32 2d 41 41 39 30 2d 30 30 30 30 30 30 30 30 30 30 30 30 7d 27 0d 0a 09 7d 0d 0a 09 53 65 61 72 63 68 48 6f 6f 6b 2e 55 52 4c 53 65 61 72 63 68 48 6f 6f 6b 20 3d 20 73 20 27 55 52 4c 53 65 61 72 63 68 48 6f 6f 6b 20 43 6c 61 73 73 27 0d 0a 09 7b 0d 0a 09 09 43 4c 53 49 44 20 3d 20 73 20 27 7b 43 35 30 36 37 46 35 39 2d 39 44 30 44 2d 31 31 44 32 2d 41 41 39 30 2d 30 30 30 30 30 30 30 30 30 30 30 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


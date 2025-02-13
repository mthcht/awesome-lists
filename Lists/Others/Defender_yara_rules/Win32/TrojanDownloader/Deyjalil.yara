rule TrojanDownloader_Win32_Deyjalil_A_2147657239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deyjalil.A"
        threat_id = "2147657239"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyjalil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "410"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {43 72 6f 73 73 72 69 64 65 72 41 70 70 30 30 30 30 34 ?? ?? 2e 53 61 6e 64 62 6f 78}  //weight: 100, accuracy: Low
        $x_100_2 = {41 70 70 30 30 30 30 34 ?? ?? 2e 46 42 41 70 69 2e 31}  //weight: 100, accuracy: Low
        $x_100_3 = "1111-110011041135} = s 'Codec-V'" ascii //weight: 100
        $x_50_4 = "TypeLib' = s '{44444444-4444-" ascii //weight: 50
        $x_50_5 = ".BHO = s 'CrossriderApp00004" ascii //weight: 50
        $x_10_6 = "2222-2222-220022042235}'" ascii //weight: 10
        $x_10_7 = "CLSID = s '{11111111-1111-1111-" ascii //weight: 10
        $x_10_8 = "ForceRemove {11111111-1111-1111-" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Deyjalil_A_2147657239_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deyjalil.A"
        threat_id = "2147657239"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyjalil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "410"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {43 72 6f 73 73 72 69 64 65 72 41 70 70 30 30 30 34 ?? ?? ?? 2e 53 61 6e 64 62 6f 78}  //weight: 100, accuracy: Low
        $x_100_2 = {41 70 70 30 30 30 34 ?? ?? ?? 2e 46 42 41 70 69 2e 31}  //weight: 100, accuracy: Low
        $x_100_3 = {31 31 31 31 2d 31 31 30 30 31 31 34 ?? ?? ?? ?? ?? 7d 20 3d 20 73 20 27 66 61 63 65 62 6f 6f 6b 20 6c 69 6c 79 20 73 79 73 74 65 6d 27}  //weight: 100, accuracy: Low
        $x_100_4 = {31 31 31 31 2d 31 31 30 30 31 31 34 ?? ?? ?? ?? ?? 7d 20 3d 20 73 20 27 54 69 6d 65 6c 69 6e 65 20 52 65 6d 6f 76 65 72 27}  //weight: 100, accuracy: Low
        $x_100_5 = {31 31 31 31 2d 31 31 30 30 31 31 34 ?? ?? ?? ?? ?? 7d 20 3d 20 73 20 27 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 41 64 64 2d 4f 6e 27}  //weight: 100, accuracy: Low
        $x_100_6 = {31 31 31 31 2d 31 31 30 30 31 31 34 ?? ?? ?? ?? ?? 7d 20 3d 20 73 20 27 41 71 6f 72 69 2e 63 6f 6d 27}  //weight: 100, accuracy: Low
        $x_100_7 = {31 31 31 31 2d 31 31 30 30 31 31 34 ?? ?? ?? ?? ?? 7d 20 3d 20 73 20 27 48 44 20 4d 65 64 69 61 20 43 6f 64 65 63 27}  //weight: 100, accuracy: Low
        $x_100_8 = "1111-110011491172} = s 'VideoFileDownload'" ascii //weight: 100
        $x_100_9 = {31 31 31 31 2d 31 31 30 30 31 31 34 ?? ?? ?? ?? ?? 7d 20 3d 20 73 20 27 41 64 2d 4b 69 6c 6c 65 72 20 50 72 6f 27}  //weight: 100, accuracy: Low
        $x_100_10 = {31 31 31 31 2d 31 31 30 30 31 31 34 ?? ?? ?? ?? ?? 7d 20 3d 20 73 20 27 41 71 6f 72 69 20 62 72 6f 77 73 65 72 20 65 78 74 65 6e 73 69 6f 6e 27}  //weight: 100, accuracy: Low
        $x_100_11 = {31 31 31 31 2d 31 31 30 30 31 31 34 ?? ?? ?? ?? ?? 7d 20 3d 20 73 20 27 46 42 4c 49 58 2d 53 4f 43 49 41 4c 27}  //weight: 100, accuracy: Low
        $x_50_12 = "TypeLib' = s '{44444444-4444-" ascii //weight: 50
        $x_50_13 = ".BHO = s 'CrossriderApp0004" ascii //weight: 50
        $x_10_14 = "2222-2222-2200224" ascii //weight: 10
        $x_10_15 = "CLSID = s '{11111111-1111-1111-" ascii //weight: 10
        $x_10_16 = "ForceRemove {11111111-1111-1111-" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_10_*))) or
            ((4 of ($x_100_*) and 1 of ($x_10_*))) or
            ((4 of ($x_100_*) and 1 of ($x_50_*))) or
            ((5 of ($x_100_*))) or
            (all of ($x*))
        )
}


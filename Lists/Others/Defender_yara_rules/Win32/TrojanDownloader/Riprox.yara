rule TrojanDownloader_Win32_Riprox_A_2147651740_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Riprox.A"
        threat_id = "2147651740"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Riprox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {37 00 35 00 33 00 63 00 64 00 61 00 38 00 62 00 30 00 35 00 65 00 33 00 32 00 65 00 66 00 33 00 62 00 38 00 32 00 65 00 30 00 66 00 66 00 39 00 34 00 37 00 61 00 34 00 61 00 39 00 33 00 36 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {34 00 33 00 38 00 64 00 62 00 65 00 34 00 34 00 64 00 65 00 31 00 37 00 63 00 66 00 39 00 37 00 64 00 32 00 37 00 64 00 64 00 36 00 36 00 62 00 61 00 30 00 30 00 37 00 61 00 39 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 65 00 74 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 48 00 65 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 00 75 00 6e 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 00 73 00 65 00 72 00 61 00 6e 00 64 00 70 00 63 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {26 00 61 00 64 00 6d 00 69 00 6e 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {26 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {44 00 4c 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {55 00 50 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {56 00 56 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {56 00 49 00 7c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}


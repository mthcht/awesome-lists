rule TrojanDownloader_Win32_Partsiosity_A_2147648690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Partsiosity.A"
        threat_id = "2147648690"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Partsiosity"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cv=%lu&uv=%ld&uc=%lu&lrp=%ld&sye=%lu" ascii //weight: 1
        $x_1_2 = {70 3a 2f 70 6c 61 79 65 72 2f 00 00 2f 70 6c 75 67 69 6e 2f}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 43 00 65 00 6e 00 74 00 65 00 72 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 53 00 63 00 6f 00 70 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b d0 83 c4 0c 83 c7 02 81 e2 01 00 00 80 79 05 4a 83 ca fe 42}  //weight: 1, accuracy: High
        $x_1_5 = {3f 64 6c 3d 31 00 00 00 66 6e 00 00 63 6c 00 00 63 73 00 00 25 6c 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


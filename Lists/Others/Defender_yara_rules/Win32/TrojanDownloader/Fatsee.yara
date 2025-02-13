rule TrojanDownloader_Win32_Fatsee_A_2147623171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fatsee.A"
        threat_id = "2147623171"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fatsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\kvsys" ascii //weight: 1
        $x_1_2 = {26 79 3d 00 3f 78 3d 00 44 4c 00 00 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_3 = {8d 44 24 10 50 b3 6c 51 c6 44 24 18 69 c6 44 24 19 65 c6 44 24 1b 70 88 5c 24 1c c6 44 24 1d 6f c6 44 24 1e 72 c6 44 24 1f 65 c6 44 24 20 2e c6 44 24 21 65 c6 44 24 23 65 c6 44 24 24 00 ff 15 d4 30 00 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


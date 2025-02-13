rule TrojanDownloader_Win32_Cordmix_A_2147651248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cordmix.A"
        threat_id = "2147651248"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cordmix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 34 78 34 73 aa e2 f8 c9}  //weight: 1, accuracy: High
        $x_1_2 = {68 52 b8 8e 7c 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {bb 3e 22 00 00 81 f3 73 78 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


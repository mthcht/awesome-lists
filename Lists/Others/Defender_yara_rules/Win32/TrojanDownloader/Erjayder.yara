rule TrojanDownloader_Win32_Erjayder_A_2147646536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Erjayder.A"
        threat_id = "2147646536"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Erjayder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4a 50 45 47 20 45 72 72 6f 72 21 00 [0-32] 2e 65 78 65 [0-16] 68 74 74 70 3a 2f 2f [0-80] 2e 6a 70 67}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


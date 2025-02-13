rule TrojanDownloader_Win32_Lisfonp_A_2147643348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lisfonp.A"
        threat_id = "2147643348"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lisfonp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/down.5201819.info/" wide //weight: 1
        $x_1_2 = {52 61 6e 67 65 3a 62 79 74 65 73 3d 25 64 2d 00 2e 75 70 67 00 00 00 00 25 64 4b 42 00 00 00 00 25 2e 32 66 4d 42}  //weight: 1, accuracy: High
        $x_1_3 = {2e 74 78 74 00 00 00 00 [0-8] 2e 69 6e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


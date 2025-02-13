rule TrojanDownloader_Win32_Belanit_A_2147652684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Belanit.A"
        threat_id = "2147652684"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Belanit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ahmet" wide //weight: 1
        $x_1_2 = {3d 4d 5a 00 00 0f 85 f0 02 00 00 8b 45 c8 6a 04 5e 83 c0 3c 56 0f 80 5a 03 00 00 50 e8 f2 fe ff ff 8b d8 56 03 5d c8 0f 80 48 03 00 00 53 e8 e0 fe ff ff 3d 50 45 00 00 0f 85 bd 02 00 00 8b c3 56 83 c0 34 0f 80 2b 03 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "fox.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


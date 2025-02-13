rule TrojanDownloader_Win32_Filsygat_A_2147728028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Filsygat.A!bit"
        threat_id = "2147728028"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Filsygat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create /tn \"fileSystem\" /tr " ascii //weight: 1
        $x_1_2 = {00 2e 63 6f 6d 00 2e 6e 65 74 00 2e 6f 72 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 2f 63 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


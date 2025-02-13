rule TrojanDownloader_Win32_Carfpos_A_2147697042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carfpos.A"
        threat_id = "2147697042"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carfpos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FuckYou" ascii //weight: 1
        $x_1_2 = {26 69 70 3d 26 6f 73 3d 00 26 76 65 72 3d 00 26 6d 61 63 3d 00 63 6f 75 6e 74 2e 61 73 70 3f 6b 65 79 3d 26 75 73 65 72 69 64 3d 00 61 64 6d 69 6e 5f 69 6e 64 65 78 2e 61 73 70}  //weight: 1, accuracy: High
        $x_1_3 = "test/<|>DNF.exe,LolClient.exe,crossfire.exe,Wow-64.exe" ascii //weight: 1
        $x_1_4 = "/love/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


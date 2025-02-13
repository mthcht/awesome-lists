rule TrojanDownloader_Win32_Roker_A_2147656234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Roker.A"
        threat_id = "2147656234"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Roker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%APPDATA%\\googlestorage.gl" ascii //weight: 1
        $x_1_2 = {2f 78 78 2f 67 61 74 65 2e 70 68 70 00 00 00 00 3f 75 69 64 3d 00 00 00 26 63 75 6e 3d 00 00 00 26 75 6e 3d}  //weight: 1, accuracy: High
        $x_1_3 = "Our mommy xoKellie\\Documents\\Visual Studio 2008\\Projects\\AnonHTTP\\Release\\AnonHTTP.pdb" ascii //weight: 1
        $x_1_4 = "Internet Host Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


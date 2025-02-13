rule TrojanDownloader_Win32_Kepier_A_2147731700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kepier.A!bit"
        threat_id = "2147731700"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kepier"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ProcessSafe.exe" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-48] 2f 74 6f 6e 67 6a 69 2e 70 68 70 3f 75 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "SELECT Name FROM Win32_Process Where Name=\"%s\"" ascii //weight: 1
        $x_1_4 = ".pbipkierrqom.life/m/uac.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


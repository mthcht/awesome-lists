rule TrojanDownloader_Win32_Blueran_A_2147730305_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Blueran.A!bit"
        threat_id = "2147730305"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Blueran"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 3b c8 7c f4 07 00 80 b1}  //weight: 1, accuracy: Low
        $x_1_2 = {59 3b f0 72 e6 15 00 80 b4 ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "\\svchost.exe" ascii //weight: 1
        $x_1_4 = "%HOMEDRIVE%%HOMEPATH%\\Local Settings\\Temp\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Ahrocam_B_2147654336_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ahrocam.B"
        threat_id = "2147654336"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ahrocam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 48 08 33 d2 66 8b 50 06 8b 74 24 18 51 52 33 c9 33 d2 66 8b 48 02 66 8b 10 51 52 68 ?? ?? ?? ?? 56 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "runinfo.exe" ascii //weight: 1
        $x_1_3 = "command=NO&result=" ascii //weight: 1
        $x_1_4 = "http-get-demo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


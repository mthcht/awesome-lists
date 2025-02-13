rule TrojanDownloader_Win32_Pacerd_2147799799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pacerd"
        threat_id = "2147799799"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pacerd"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/terms/ptf_" ascii //weight: 3
        $x_1_2 = "Internet Explorer 6.0AD1" ascii //weight: 1
        $x_3_3 = ".pacimedia.com" ascii //weight: 3
        $x_3_4 = "Projects\\pacerd\\stub\\" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


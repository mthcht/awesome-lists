rule TrojanDownloader_Win32_Shen_A_2147597958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Shen.A"
        threat_id = "2147597958"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Shen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "zn5b.com/ggbh/ggbh.cgi?" ascii //weight: 1
        $x_1_3 = "chenznwb.exe" ascii //weight: 1
        $x_1_4 = "dmshell.dll" ascii //weight: 1
        $x_1_5 = "CreateMutexW" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Qhelp_A_2147597957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Qhelp.A"
        threat_id = "2147597957"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhelp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "pbqc.com/f2/up.dat?" ascii //weight: 1
        $x_1_3 = "QqHelperJ.dll" ascii //weight: 1
        $x_1_4 = "Software\\Adobe" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "HttpQueryInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


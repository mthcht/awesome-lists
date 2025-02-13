rule TrojanDownloader_Win32_Malsia_A_2147599213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Malsia.A"
        threat_id = "2147599213"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Malsia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVCP60.dll" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "malaysia.bbccddeeffgg.com" ascii //weight: 1
        $x_1_4 = "ppl1.cmn" ascii //weight: 1
        $x_1_5 = "Software\\malaysia" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_8 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_VBKrypt_HAZ_2147754518_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VBKrypt.HAZ!MTB"
        threat_id = "2147754518"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VBVM60.DLL" ascii //weight: 1
        $x_1_2 = "http://www.sunqtr.com/upload/wh_52738169.exe" ascii //weight: 1
        $x_1_3 = "c:\\serv.exe" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


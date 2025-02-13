rule TrojanDownloader_Win32_TinyDow_A_2147837871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/TinyDow.A!MTB"
        threat_id = "2147837871"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Urlmon.dll" ascii //weight: 1
        $x_1_2 = "LoadLibraryA" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_2_5 = "://oceanofcheats.com/thecoloryellowv3/love.au3" wide //weight: 2
        $x_2_6 = "://oceanofcheats.com/thecoloryellowv3/AutoIt3.exe" wide //weight: 2
        $x_2_7 = ":\\ProgramData\\love.exe" wide //weight: 2
        $x_2_8 = ":\\ProgramData\\love.au3" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


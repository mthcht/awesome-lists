rule TrojanDownloader_Win32_Apost_CA_2147838315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Apost.CA!MTB"
        threat_id = "2147838315"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Apost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%USERPROFILE%\\\\1728.ico.log.vbs" ascii //weight: 1
        $x_1_2 = "InstallPath=\"%TEMP%\"" ascii //weight: 1
        $x_1_3 = "UploadString('http://bintors.ru/get.php','')" ascii //weight: 1
        $x_1_4 = "%USERPROFILE%\\ntuser.txt" ascii //weight: 1
        $x_1_5 = "!@InstallEnd@!" ascii //weight: 1
        $x_1_6 = "SelfDelete=\"1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanSpy_Win32_Rukhami_S_2147728338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rukhami.S"
        threat_id = "2147728338"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rukhami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Torrents Downloader" ascii //weight: 1
        $x_1_2 = "adulthubnew.club" ascii //weight: 1
        $x_1_3 = "payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


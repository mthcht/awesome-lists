rule TrojanDownloader_Win32_Alphabet_2147596910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Alphabet"
        threat_id = "2147596910"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Alphabet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%s\\%s%s.exe" ascii //weight: 10
        $x_10_2 = "http://s2.bestmanage.org/?name=%s" ascii //weight: 10
        $x_10_3 = "InternetSetOptionA" ascii //weight: 10
        $x_10_4 = "InternetCheckConnectionA" ascii //weight: 10
        $x_1_5 = "_self" ascii //weight: 1
        $x_1_6 = "agent" ascii //weight: 1
        $x_1_7 = "power" ascii //weight: 1
        $x_1_8 = "Clicks" ascii //weight: 1
        $x_1_9 = "ToFeed" ascii //weight: 1
        $x_1_10 = "ClickTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


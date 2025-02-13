rule TrojanDownloader_Win32_Exwamp_A_2147630574_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Exwamp.A"
        threat_id = "2147630574"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Exwamp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\wamp\\www\\dx-exploit\\" ascii //weight: 1
        $x_1_2 = {74 07 c1 cf 0d 01 c7 eb f2 3b 7c 24 14 75 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


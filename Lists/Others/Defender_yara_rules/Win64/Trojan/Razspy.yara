rule Trojan_Win64_Razspy_YBQ_2147919874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Razspy.YBQ!MTB"
        threat_id = "2147919874"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Razspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%swallpaper.png" ascii //weight: 1
        $x_1_2 = "http://118.243.83.70/" ascii //weight: 1
        $x_1_3 = "http://73.55.128.120/" ascii //weight: 1
        $x_1_4 = "QzpcV2luZG93c1xUZW1wXFJhenJ1c2hlbml5ZS5leGU=" ascii //weight: 1
        $x_1_5 = ".pythonanywhere.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


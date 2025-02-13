rule Trojan_Win32_VenomSpider_2147832882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VenomSpider!MTB"
        threat_id = "2147832882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VenomSpider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {8b 45 08 8b 4d 0c 8b 11 89 10 8b 45 08 83 c0 04 89 45 08 8b 4d 0c 83 c1 04 89 4d 0c 8b 55 10 83 ea 02 89 55 10}  //weight: 8, accuracy: High
        $x_1_2 = "FileSeek16" ascii //weight: 1
        $x_1_3 = "FileInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_RedCurl_DA_2147943428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedCurl.DA!MTB"
        threat_id = "2147943428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCurl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 07 4c 8d 0c 02 48 8b c3 48 83 7b 18 10 72 ?? 48 8b 03 0f b6 14 01 41 32 11 48 8b c6 48 83 7e 18 10 72 ?? 48 8b 06 88 14 01 41 ff c0 48 ff c1 49 63 c0 48 3b 43 10 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


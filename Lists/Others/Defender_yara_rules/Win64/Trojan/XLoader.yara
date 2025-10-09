rule Trojan_Win64_XLoader_GVA_2147954704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XLoader.GVA!MTB"
        threat_id = "2147954704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d1 48 8d 44 10 10 0f b6 00 48 8b 4d c0 30 01 8b 45 d8 ff c0 89 45 d8 8b 45 d8 3b 45 dc 0f 9c c0 0f b6 c0 89 45 d4 83 7d d4 00 75 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


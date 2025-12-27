rule Trojan_Win64_PureLogsStealer_TBK_2147955228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PureLogsStealer.TBK!MTB"
        threat_id = "2147955228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 04 11 83 e0 ?? 29 c8 48 98 41 0f b6 04 01 41 30 04 10 48 83 c2 ?? 48 81 fa}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


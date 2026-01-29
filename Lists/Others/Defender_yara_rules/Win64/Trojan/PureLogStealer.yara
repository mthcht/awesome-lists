rule Trojan_Win64_PureLogStealer_GTV_2147961984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PureLogStealer.GTV!MTB"
        threat_id = "2147961984"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "f37dc047e228b99b50e9443022" ascii //weight: 5
        $x_5_2 = "d24b6e460ba84c224930da" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


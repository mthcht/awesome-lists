rule Trojan_Win64_Xenon_KK_2147968284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xenon.KK!MTB"
        threat_id = "2147968284"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xenon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b 85 bc 00 00 00 48 98 0f b6 54 05 30 8b 85 bc 00 00 00 48 98 0f b6 44 05 70 31 c2 8b 85 bc 00 00 00 48 98 88 54 05 30 8b 85 bc 00 00 00 48 98 0f b6 54 05 f0 8b 85 bc 00 00 00 48 98 0f b6 44 05 70 31 c2 8b 85 bc 00 00 00 48 98 88 54 05 f0 83 85 bc 00 00 00 01}  //weight: 20, accuracy: High
        $x_5_2 = "Beacon" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_ShadowHost_A_2147982927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShadowHost.A!MTB"
        threat_id = "2147982927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShadowHost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {48 01 d0 48 8b 8d e0 fe ff ff 0f b6 09 0f b6 00 31 c1 48 8b 85 e0 fe ff ff 88 08 e9}  //weight: 30, accuracy: High
        $x_20_2 = {88 11 8b 85 f8 fe ff ff 48 8d 8d 00 ff ff ff 48 01 c1 0f b6 85 ec fe ff ff 88 01 e9}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Stealerc_GPA_2147916632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealerc.GPA!MTB"
        threat_id = "2147916632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XEBWZZk<uCEBY[rSEB_XWB_YX" ascii //weight: 1
        $x_1_2 = "dCXfDSeSBCFuY[[WXREeSUB_YX<" ascii //weight: 1
        $x_1_3 = "<mdCXfDSeSBCFuY[[WXREeSUB_YXk<dsfzwusiuy{{wxriz" ascii //weight: 1
        $x_1_4 = "xs<BWE]]_ZZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealerc_NV_2147931488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealerc.NV!MTB"
        threat_id = "2147931488"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 1d 4b b8 2b 00 33 f6 f6 03 02 74 ?? 48 8b 7b 10 eb ?? 45 33 c9 4c 8d 44 24 58 48 8d 15 6f b4 22 00 48 8b cb e8 ?? ?? ?? ?? 84 c0 48 8b}  //weight: 3, accuracy: Low
        $x_1_2 = "stealer_bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


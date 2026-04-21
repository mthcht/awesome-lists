rule Trojan_Win64_DedukPswStealer_MX_2147967444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DedukPswStealer.MX!MTB"
        threat_id = "2147967444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DedukPswStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {30 03 0f b6 03 41 03 c7 25 ff 00 00 80 7d 09 ff c8 0d 00 ff ff ff ff c0 48 ff c3 48 3b d9 72 e0}  //weight: 5, accuracy: High
        $x_1_2 = "lambda-url.eu-north-1.on.aws" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


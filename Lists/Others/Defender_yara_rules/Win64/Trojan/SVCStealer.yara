rule Trojan_Win64_SVCStealer_SX_2147945951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SVCStealer.SX!MTB"
        threat_id = "2147945951"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SVCStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f be 37 8b ce e8 ?? ?? ?? ?? 85 c0 75 09 40 80 fe 5f 74 03 c6 07 5f 48 ff c7 48 3b fb 75 e1}  //weight: 20, accuracy: Low
        $x_10_2 = {4c 89 7c 24 38 4c 89 7c 24 30 44 89 7c 24 28 4c 89 7c 24 20 41 83 c9 ff 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 63 f8 48 c7 44 24 78 0f 00 00 00 4c 89 7c 24 70 44 88 7c 24 60 48 8b d7 45 33 c0 48 8d 4c 24 60 e8}  //weight: 10, accuracy: Low
        $x_5_3 = "9APARW83Z6" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


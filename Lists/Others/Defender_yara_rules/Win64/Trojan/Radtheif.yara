rule Trojan_Win64_Radtheif_AHB_2147952970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radtheif.AHB!MTB"
        threat_id = "2147952970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radtheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {4c 8b 94 24 f0 00 00 00 4c 8b 9c 24 d8 00 00 00 44 0f b6 64 24 43 48 89 c6 48 89 cb 48 8b 44 24 50 48 8b 4c 24 60 e9}  //weight: 20, accuracy: High
        $x_30_2 = {48 8d 34 d9 48 8b 38 48 89 3c 30 48 ff c3 48 8d 72 ff 48 39 f3 7c}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


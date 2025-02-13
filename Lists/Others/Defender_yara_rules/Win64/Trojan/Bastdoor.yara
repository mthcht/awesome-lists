rule Trojan_Win64_Bastdoor_MKV_2147926600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bastdoor.MKV!MTB"
        threat_id = "2147926600"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bastdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 31 ed 48 83 e1 03 74 ?? 66 0f 1f 84 00 00 00 00 00 42 0f b6 54 2c ?? 43 30 14 2c 49 ff c5 4c 39 e9 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


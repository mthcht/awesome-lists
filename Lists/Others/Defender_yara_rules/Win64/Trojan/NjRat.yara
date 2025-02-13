rule Trojan_Win64_NjRat_NEBG_2147838654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NjRat.NEBG!MTB"
        threat_id = "2147838654"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 41 96 30 44 0c ?? 48 ff c1 48 83 f9 ?? 72 f0 c6}  //weight: 10, accuracy: Low
        $x_1_2 = "71.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_RadRat_A_2147978153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RadRat.A!MTB"
        threat_id = "2147978153"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RadRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {42 0f b6 84 01 70 a5 01 00 48 8d 49 01 34 5a 88 44 0c 6f 48 83 ea 01}  //weight: 20, accuracy: High
        $x_15_2 = {48 ff c3 48 8d 04 17 88 8c ?? ?? ?? ?? 00 48 ff c2 0f b6 0b 80 f9}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


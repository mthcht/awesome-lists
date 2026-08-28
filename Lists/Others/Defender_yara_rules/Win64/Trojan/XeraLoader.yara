rule Trojan_Win64_XeraLoader_PAHJ_2147977148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XeraLoader.PAHJ!MTB"
        threat_id = "2147977148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XeraLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 17 41 8b c1 83 e2 1f c1 e0 05 44 8b ca 83 c1 05 44 0b c8 83 f9 08}  //weight: 3, accuracy: High
        $x_2_2 = {83 c1 f8 41 8b c1 d3 e8 41 88 00 48 83 eb 01 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


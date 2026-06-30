rule Trojan_Win64_AveMariaRat_BDA_2147972581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AveMariaRat.BDA!MTB"
        threat_id = "2147972581"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 34 03 48 8b 94 24 ?? ?? ?? ?? 31 d6 31 de 40 88 34 18 48 ff c3 48 8b 8c 24 ?? ?? ?? ?? 48 39 d9 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


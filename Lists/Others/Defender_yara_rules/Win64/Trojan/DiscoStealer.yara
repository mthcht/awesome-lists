rule Trojan_Win64_DiscoStealer_MK_2147964950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscoStealer.MK!MTB"
        threat_id = "2147964950"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {33 d2 48 8d 49 01 41 8b c1 41 ff c1 41 f7 f6 0f b6 04 3a 32 44 0b ff 88 41 ff 44 3b ce}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


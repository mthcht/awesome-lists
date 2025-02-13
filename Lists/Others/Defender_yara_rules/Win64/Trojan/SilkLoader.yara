rule Trojan_Win64_SilkLoader_MA_2147849574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilkLoader.MA!MTB"
        threat_id = "2147849574"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilkLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b c8 34 41 8a c0 41 ff c0 2a c1 04 35 41 30 01 49 ff c1 41 83 f8 16 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


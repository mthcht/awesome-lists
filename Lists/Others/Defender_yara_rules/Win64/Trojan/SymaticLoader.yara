rule Trojan_Win64_SymaticLoader_RPV_2147835182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SymaticLoader.RPV!MTB"
        threat_id = "2147835182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SymaticLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 01 48 8d 49 01 2c 0a 34 cc 88 41 ff 48 83 ea 01 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


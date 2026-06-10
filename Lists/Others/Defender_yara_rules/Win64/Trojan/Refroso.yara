rule Trojan_Win64_Refroso_ABKV_2147971329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Refroso.ABKV!MTB"
        threat_id = "2147971329"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Refroso"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c1 83 e1 03 8a 4c 0c ?? 30 0c 06 48 ff c0 48 39 c7 75}  //weight: 5, accuracy: Low
        $x_5_2 = {44 8a 04 08 41 80 f0 ?? 44 88 04 10 48 ff c0 48 83 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


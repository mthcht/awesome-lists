rule Trojan_Win64_GoDro_CR_2147981434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoDro.CR!MTB"
        threat_id = "2147981434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoDro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 c7 48 89 f0 49 89 d3 31 d2 49 f7 f3 45 0f b6 24 11 45 31 e2 44 88 14 37 48 ff c6 48 89 f8 4c 89 da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


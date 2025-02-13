rule Ransom_Win64_Kransom_GA_2147926851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Kransom.GA!MTB"
        threat_id = "2147926851"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Kransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 31 aa 48 ff c1 48 83 ea 01 75 f4}  //weight: 2, accuracy: High
        $x_1_2 = "I believe you've encountered some problems" ascii //weight: 1
        $x_1_3 = "\\what.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


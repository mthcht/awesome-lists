rule Ransom_Win64_Crimson_MRZ_2147966053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crimson.MRZ!MTB"
        threat_id = "2147966053"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crimson"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 3
        $x_3_2 = "CRIMSON RANSOMWARE v5.0" ascii //weight: 3
        $x_3_3 = "!!!_CRIMSON_README_!!!.txt" ascii //weight: 3
        $x_1_4 = "Send %d BTC to" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


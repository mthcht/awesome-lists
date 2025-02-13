rule Ransom_Win64_Gojdu_A_2147725518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gojdu.A"
        threat_id = "2147725518"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gojdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_2 = ">Your files have been encrypted." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


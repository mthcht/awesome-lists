rule Ransom_Win64_BlackSpider_PA_2147960329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackSpider.PA!MTB"
        threat_id = "2147960329"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackSpider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build" ascii //weight: 1
        $x_1_2 = "R3ADM3.txt" ascii //weight: 1
        $x_3_3 = "[BL4CK SP1D3R RANSOMWARE]" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


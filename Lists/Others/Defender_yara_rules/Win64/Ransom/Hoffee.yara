rule Ransom_Win64_Hoffee_PAD_2147794699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hoffee.PAD!MTB"
        threat_id = "2147794699"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hoffee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HotCoffeeRansomware.pdb" ascii //weight: 1
        $x_1_2 = "HOT_COFFEE_README.hta" ascii //weight: 1
        $x_1_3 = "aaa_TouchMeNot_.txt" ascii //weight: 1
        $x_1_4 = "password123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


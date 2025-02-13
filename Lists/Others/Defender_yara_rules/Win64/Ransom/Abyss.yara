rule Ransom_Win64_Abyss_AA_2147914890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Abyss.AA!MTB"
        threat_id = "2147914890"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Abyss"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".lock" wide //weight: 1
        $x_1_2 = ".Abyss" wide //weight: 1
        $x_1_3 = "WhatHappened.txt" wide //weight: 1
        $x_1_4 = "key.pub" wide //weight: 1
        $x_1_5 = "we will permanently delete all your data from our servers" ascii //weight: 1
        $x_1_6 = "payment and decryption" ascii //weight: 1
        $x_1_7 = "We are the Abyss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


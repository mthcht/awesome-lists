rule Ransom_Win64_Monolock_GVA_2147955788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Monolock.GVA!MTB"
        threat_id = "2147955788"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Monolock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 49 18 48 89 f8 ff d1 83 f0 01 48 8b 54 24 30 48 8b 5c 24 78 4c 8b 44 24 38 4c 8b 4c 24 28 89 c1 48 8b 44 24 70}  //weight: 2, accuracy: High
        $x_1_2 = "README_RECOVER.txt" ascii //weight: 1
        $x_1_3 = "YOUR FILES HAVE BEEN ENCRYPTE" ascii //weight: 1
        $x_1_4 = ".onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Monolock_GVB_2147955789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Monolock.GVB!MTB"
        threat_id = "2147955789"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Monolock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 30 48 33 35 d1 29 db 00 48 8b 78 08 48 31 df 48 89 c3 48 89 f8 48 89 d7 48 f7 e6 90 90 90 48 31 d0 90 48 83 c1 f0 48 8d 73 10 48 89 fa 48 89 c3 48 89 f0 48 83 f9 10 77 c5}  //weight: 1, accuracy: High
        $x_2_2 = "main.(*xMv0HCkHIyj).Replace" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


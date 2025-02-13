rule Ransom_Win64_SeivCrypt_PA_2147838447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SeivCrypt.PA!MTB"
        threat_id = "2147838447"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SeivCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".seiv" ascii //weight: 1
        $x_1_2 = {5c 70 72 69 76 61 74 65 [0-16] 2e 65 6e 63 72 79 70 74 65 64}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 41 72 74 4f 66 43 72 79 70 74 5c [0-21] 5c 45 4e 63 72 79 70 74 30 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


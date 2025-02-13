rule Ransom_Win32_NotPetya_PA_2147915022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NotPetya.PA!MTB"
        threat_id = "2147915022"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NotPetya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\README.TXT" ascii //weight: 1
        $x_1_2 = "EncryptingC4Fun!" ascii //weight: 1
        $x_3_3 = {5c 50 61 79 6c 6f 61 64 73 5c 4e 6f 74 5f 50 65 74 79 61 5f 58 4f 52 5f 44 6c 6c 5c [0-8] 5c 52 65 6c 65 61 73 65 5c 4e 6f 74 5f 50 65 74 79 61 5f 44 6c 6c 2e 70 64 62}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


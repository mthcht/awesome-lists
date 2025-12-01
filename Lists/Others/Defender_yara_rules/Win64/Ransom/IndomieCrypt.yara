rule Ransom_Win64_IndomieCrypt_PA_2147958595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/IndomieCrypt.PA!MTB"
        threat_id = "2147958595"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "IndomieCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BCryptEncrypt" ascii //weight: 1
        $x_3_2 = {5c 49 6e 64 6f 6d 69 65 20 52 61 6e 73 6f 6d 77 61 72 65 5c [0-64] 5c 49 6e 64 6f 6d 69 65 20 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


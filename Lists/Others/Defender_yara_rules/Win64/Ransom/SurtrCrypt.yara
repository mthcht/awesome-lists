rule Ransom_Win64_SurtrCrypt_PA_2147814360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SurtrCrypt.PA!MTB"
        threat_id = "2147814360"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SurtrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CryptDecrypt" ascii //weight: 1
        $x_1_2 = "Payload successfully decrypted" ascii //weight: 1
        $x_1_3 = {5c 00 44 00 72 00 6f 00 70 00 70 00 65 00 72 00 5c 00 [0-4] 5c 00 [0-16] 5c 00 44 00 72 00 6f 00 70 00 70 00 65 00 72 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 44 72 6f 70 70 65 72 5c [0-4] 5c [0-16] 5c 44 72 6f 70 70 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


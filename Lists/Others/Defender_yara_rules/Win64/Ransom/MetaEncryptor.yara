rule Ransom_Win64_MetaEncryptor_SA_2147897227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MetaEncryptor.SA!MTB"
        threat_id = "2147897227"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MetaEncryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "we will NOT encrypt this file now or later" ascii //weight: 1
        $x_1_2 = "reencrypt" ascii //weight: 1
        $x_1_3 = "encrypt_decrypt_direntry" ascii //weight: 1
        $x_1_4 = "readme file exists" ascii //weight: 1
        $x_1_5 = "expand 32-byte kexpand 32-byte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


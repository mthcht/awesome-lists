rule Ransom_MSIL_MosnCrypt_MK_2147787786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/MosnCrypt.MK!MTB"
        threat_id = "2147787786"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MosnCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INFORMATION_READ_ME.txt" ascii //weight: 1
        $x_1_2 = "FILES-ENCRYPTED:" ascii //weight: 1
        $x_1_3 = "HARDWARE-ID_INCLUDE_IN_MAIL:" ascii //weight: 1
        $x_1_4 = "ENCRYPTED_MEMORY_STRINGS" ascii //weight: 1
        $x_1_5 = "EncryptAllFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


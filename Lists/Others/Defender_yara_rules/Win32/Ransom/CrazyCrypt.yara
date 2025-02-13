rule Ransom_Win32_CrazyCrypt_PA_2147788222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CrazyCrypt.PA!MTB"
        threat_id = "2147788222"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CrazyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CrazyCrypt_Encrypt" ascii //weight: 1
        $x_1_2 = "Your files have been encrypted" ascii //weight: 1
        $x_1_3 = "/C choice /C Y /N /D Y /T 3 & Del \"" ascii //weight: 1
        $x_1_4 = "Your private key will be destroyed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


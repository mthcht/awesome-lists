rule Ransom_Win32_Encoder_MX_2147959501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Encoder.MX!MTB"
        threat_id = "2147959501"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 83 c4 0c 48 a3 fc 44 01 02 89 35 00 45 01 02 33 c0 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Encoder_NE_2147962191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Encoder.NE!MTB"
        threat_id = "2147962191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "RANSOMWARE SIMULATOR - ENCRYPTOR" ascii //weight: 3
        $x_1_2 = "ENCRYPTION COMPLETE" ascii //weight: 1
        $x_1_3 = "password123Encrypted" ascii //weight: 1
        $x_1_4 = "encryptor.exedecryptor.exe" ascii //weight: 1
        $x_1_5 = "All your files have been encrypted" ascii //weight: 1
        $x_1_6 = "To decrypt, use the decryptor with password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


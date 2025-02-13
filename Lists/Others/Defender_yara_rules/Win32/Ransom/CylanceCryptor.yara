rule Ransom_Win32_CylanceCryptor_ND_2147847325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CylanceCryptor.ND!MTB"
        threat_id = "2147847325"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CylanceCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 86 10 07 42 00 50 68 58 12 42 00 57 ff d3 46 83 c4 0c 83 c7 02 83 fe 08 7c e4}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 03 8d 5b 01 8b ce c1 e6 08 c1 e9 18 33 c8 33 34 8d 10 ef 41 00 83 ea 01 75 e4}  //weight: 1, accuracy: High
        $x_1_3 = "Your Decryption ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


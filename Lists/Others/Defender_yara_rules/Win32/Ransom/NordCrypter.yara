rule Ransom_Win32_NordCrypter_YAA_2147915635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NordCrypter.YAA!MTB"
        threat_id = "2147915635"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NordCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 43 f3 33 d2 f7 75 fc 47 8a 04 32 8b 55 f8 32 04 0a 8b 55 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


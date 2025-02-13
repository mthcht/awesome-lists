rule Ransom_Win32_ContiCryptor_MAK_2147794869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCryptor.MAK!MTB"
        threat_id = "2147794869"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 c2 20 46 c1 c1 [0-1] 03 f5 0f be c2 33 c8 43 8a 16 84 d2 75 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


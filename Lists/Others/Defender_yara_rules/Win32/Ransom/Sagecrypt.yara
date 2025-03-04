rule Ransom_Win32_SageCrypt_PAA_2147809854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SageCrypt.PAA!MTB"
        threat_id = "2147809854"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SageCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 3d 04 f5 14 11 00 75 1b 8b 4d d0 3b cf 7d 14 8b 45 d4 0f af c6 99 f7 7d d8 6b c9 e3 2b c8 03 f1 89 75 dc 47 89 7d c0 8b 4d d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


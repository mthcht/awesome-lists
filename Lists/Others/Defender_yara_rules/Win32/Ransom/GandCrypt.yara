rule Ransom_Win32_GandCrypt_DA_2147777156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrypt.DA!MTB"
        threat_id = "2147777156"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GDCB-DECRYPT.txt" ascii //weight: 1
        $x_1_2 = "ransom_id" ascii //weight: 1
        $x_1_3 = "GandCrab" ascii //weight: 1
        $x_1_4 = "CryptGenKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrypt_DB_2147899394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrypt.DB!MTB"
        threat_id = "2147899394"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d f4 7d ?? 8b 55 f8 03 55 fc 0f be 1a e8 ?? ?? ?? ?? 33 d8 8b 45 f8 03 45 fc 88 18 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrypt_EAAN_2147937891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrypt.EAAN!MTB"
        threat_id = "2147937891"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 94 06 32 09 00 00 88 14 08 8b 7c 24 10 40 3b c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win32_HiveCrypt_MP_2147809009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HiveCrypt.MP!MTB"
        threat_id = "2147809009"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HiveCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 02 57 45 58 02 57 45 58}  //weight: 1, accuracy: High
        $x_1_2 = {88 58 14 0f b6 5c 24 6c 0f b6 ac 24 d6 04 00 00 31 eb 88 58 15 0f b6 9c 24 f9 04 00 00 0f b6 ac 24 d7 04 00 00 29 eb 88 58 16}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 ac 24 64 02 00 00 01 eb 88 98 95 00 00 00 0f b6 9c 24 59 04 00 00 0f b6 ac 24 3e 04 00 00 31 eb 88 98 96 00 00 00 0f b6 9c 24 3d 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_HiveCrypt_PB_2147828891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HiveCrypt.PB!MTB"
        threat_id = "2147828891"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HiveCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go buildinf:" ascii //weight: 1
        $x_1_2 = "crypto/aes.encryptBlockGo" ascii //weight: 1
        $x_1_3 = "crypto/aes.expandKeyGo" ascii //weight: 1
        $x_1_4 = "path/filepath.WalkDir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


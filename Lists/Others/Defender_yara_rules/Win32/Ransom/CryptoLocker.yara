rule Ransom_Win32_CryptoLocker_MAK_2147796541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoLocker.MAK!MTB"
        threat_id = "2147796541"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/landing" ascii //weight: 1
        $x_1_2 = "/wipe" ascii //weight: 1
        $x_1_3 = "/ext" ascii //weight: 1
        $x_1_4 = "/ignore" ascii //weight: 1
        $x_1_5 = "/priority" ascii //weight: 1
        $x_1_6 = "/services" ascii //weight: 1
        $x_1_7 = "/key" ascii //weight: 1
        $x_10_8 = "GENBOTID" ascii //weight: 10
        $x_1_9 = "KILLPR begin" ascii //weight: 1
        $x_1_10 = "KILLPR end" ascii //weight: 1
        $x_1_11 = "SMBFAST begin" ascii //weight: 1
        $x_1_12 = "SMBFAST end" ascii //weight: 1
        $x_1_13 = "DeletingFiles" ascii //weight: 1
        $x_10_14 = "README_FOR_DECRYPT.txt" ascii //weight: 10
        $x_10_15 = "%cid_bot%" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_CryptoLocker_MZZ_2147952175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoLocker.MZZ!MTB"
        threat_id = "2147952175"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = ":Darknet" ascii //weight: 4
        $x_3_2 = "Some files on your computer have been encrypted and saved by me." ascii //weight: 3
        $x_2_3 = "How do I recover my important files?" ascii //weight: 2
        $x_1_4 = "d0glun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CryptoLocker_KQP_2147958408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoLocker.KQP!MTB"
        threat_id = "2147958408"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c7 0f 43 75 20 83 bd 24 ff ff ff 08 0f 43 8d 10 ff ff ff 33 d2 f7 b5 20 ff ff ff 66 8b 04 51 8d 8d e0 fe ff ff 66 33 04 7e 0f b7 c0 50 6a 01 e8 ?? ?? ?? ?? 47 3b 7d 30 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


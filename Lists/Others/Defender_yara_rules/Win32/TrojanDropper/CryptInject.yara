rule TrojanDropper_Win32_CryptInject_DH_2147816548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/CryptInject.DH!MTB"
        threat_id = "2147816548"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 0e 32 55 18 88 16 46 ff 4d 14 75 f2}  //weight: 2, accuracy: High
        $x_2_2 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_CryptInject_DI_2147819631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/CryptInject.DI!MTB"
        threat_id = "2147819631"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 fb 8b 5d f8 0f b6 c2 89 45 f4 88 55 fd 8a 54 08 04 8d 44 08 04 88 16 8a 55 ff 88 10 8b 45 08 03 d8 0f b6 06 0f b6 d2 03 c2 be 00 01 00 00 99 f7 fe 0f b6 c2 8a 44 08 04 30 03 ff 45 f8 8b 45 f8 3b 45 0c 72 90}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_CryptInject_BH_2147827636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/CryptInject.BH!MTB"
        threat_id = "2147827636"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c0 8a 19 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 da 40 88 19 41 4e 75}  //weight: 2, accuracy: High
        $x_2_2 = {66 89 54 24 0c 66 89 44 24 0e 66 89 74 24 10 66 89 74 24 14 66 89 4c 24 16 66 89 44 24 18 66 89 54 24 1a 66 89 44 24 1c 66 89 74 24 1e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_CryptInject_PACF_2147897754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/CryptInject.PACF!MTB"
        threat_id = "2147897754"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 0c 90 40 00 8d 7e 01 ba 1c f8 47 00 8a 44 38 ff 8a 54 1a ff 30 c2 8b 7d c0 8d 04 37 88 10 39 f1 77 cb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


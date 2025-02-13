rule Trojan_Win32_ContiCrypt_XO_2147812643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ContiCrypt.XO!MTB"
        threat_id = "2147812643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 19 8d 34 10 02 da 42 30 1e 83 fa}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 c0 0f 47 d0 83 c1 02 0f b7 c2 43 33 f0 89 4d f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ContiCrypt_OO_2147812650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ContiCrypt.OO!MTB"
        threat_id = "2147812650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af c6 88 6d f2 b9 05 00 00 00 99 f7 f9 0f be 45 e9 8b 8d 70 ff ff ff 03 c3 0f be f2 33 c6 23 c8}  //weight: 1, accuracy: High
        $x_1_2 = {33 14 e4 83 c4 04 81 e7 00 00 00 00 8b 3c e4 83 ec fc 31 f6 0b 34 e4 83 c4 04 31 db 8b 1c e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ContiCrypt_CMN_2147813318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ContiCrypt.CMN!MTB"
        threat_id = "2147813318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c1 0b f7 e9 03 d1 c1 fa 04 8b c2 c1 e8 1f 03 c2}  //weight: 1, accuracy: High
        $x_1_2 = {83 c1 0b f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


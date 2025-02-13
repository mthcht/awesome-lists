rule Trojan_Win32_VidarCrypt_PAA_2147816651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarCrypt.PAA!MTB"
        threat_id = "2147816651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3 01 08 c3 55 8b ec 81 ec e8 0a 00 00 8b 45 08}  //weight: 1, accuracy: High
        $x_1_2 = {d3 e6 8b 4d f4 8b c2 d3 e8 03 b5 ?? ?? ?? ?? 89 45 fc 8b 85 ?? ?? ?? ?? 01 45 fc 8d 04 17 33 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarCrypt_PAC_2147819220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarCrypt.PAC!MTB"
        threat_id = "2147819220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 c8 8d 04 3b 33 c8 89 4d fc 8b 45 fc [0-15] 2b f1 8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 e8 8d 14 33 33 ca 33 c8 2b f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarCrypt_PAD_2147819411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarCrypt.PAD!MTB"
        threat_id = "2147819411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 ?? 03 4d ec 03 c2 33 c8 8d 04 3b 33 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {2b f1 8b ce c1 e1 ?? 03 4d f0 8b c6 c1 e8 ?? 03 45 f4 8d 14 33 33 ca 33 c8 2b f9 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarCrypt_PAE_2147819412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarCrypt.PAE!MTB"
        threat_id = "2147819412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 45 80 8b 45 80 8b 4d 70 d3 e8 89 45 74 8b 85 68 ff ff ff 01 45 74 8b 75 80 8b 4d 84 03 4d 80 c1 e6 ?? 03 b5 70 ff ff ff 33 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 2b f8 ff 8d 78 ff ff ff 89 bd 7c ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


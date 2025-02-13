rule Trojan_Win32_CryptOne_MKVC_2147831504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptOne.MKVC!MTB"
        threat_id = "2147831504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptOne"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptOne_CBYB_2147853069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptOne.CBYB!MTB"
        threat_id = "2147853069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptOne"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 a4 8b 45 ec 8b 55 d8 01 02 8b 45 a8 03 45 9c 03 45 ec 03 45 a4 89 45 ac 8b 45 ac 8b 55 d8 31 02 83 45 ec ?? 83 45 d8 ?? 8b 45 ec 3b 05 d4 dd 5b 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptOne_CCCG_2147892544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptOne.CCCG!MTB"
        threat_id = "2147892544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptOne"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 43 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 8b 45 f8 83 c0 ?? 89 45 f8 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 45 f8 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


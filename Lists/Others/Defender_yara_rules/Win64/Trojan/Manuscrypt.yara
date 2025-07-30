rule Trojan_Win64_Manuscrypt_RI_2147836569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Manuscrypt.RI!MTB"
        threat_id = "2147836569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinOsClientProject\\x64\\Release-exe" ascii //weight: 1
        $x_1_2 = "GFIRestart64.exe" wide //weight: 1
        $x_1_3 = {48 8b cb 41 f7 e3 44 2b da b8 05 41 10 04 41 d1 eb 44 03 da 41 c1 eb 09 41 f7 e3 44 2b da 41 d1 eb 44 03 da ba 3c 00 00 00 41 c1 eb 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Manuscrypt_ARAX_2147947860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Manuscrypt.ARAX!MTB"
        threat_id = "2147947860"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 74 04 60 3a 48 ff c0 48 3d 8c 0a 00 00 7c f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


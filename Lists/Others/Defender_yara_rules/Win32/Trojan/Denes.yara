rule Trojan_Win32_Denes_GHM_2147844542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Denes.GHM!MTB"
        threat_id = "2147844542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Denes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7a 98 f3 46 c7 45 ?? f3 ec cb 5f c7 45 ?? fc 9d 96 70 c7 45 ?? c2 4e d7 0a c7 45 ?? 39 c6 57 34 c7 45 ?? 58 f8 60 29 c7 45 ?? 82 cf 7a 19 c7 45 ?? 00 31 fa 01 c7 45 ?? 4c cb e1 5d c7 45 ?? 41 2b b2 27 c7 45 ?? 03 ce 67 32 c7 45 ?? 8e f1 8e 41 c7 45 ?? 34 20 d1 67 c7 45 ?? 37 dd e8 61 c7 45 ?? 0f be c9 19 c7 45 ?? 7e 48 6c 15 c7 45 ?? 0e 02 ab 1b c7 45 ?? 19 db 2c 3c c7 45 ?? bb 06 c4 5b c7 45 ?? a7 69 c4 77 c7 45 ?? b7 df 21 76 c7 45 ?? 89 12 4d 4a c7 45 ?? 56 35 64 6a c7 85 ?? ?? ?? ?? d8 4c 91 33}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Denes_GE_2147924610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Denes.GE!MTB"
        threat_id = "2147924610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Denes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 ff cf 31 79 b6 a2 ?? ?? ?? ?? 18 65 83 49}  //weight: 5, accuracy: Low
        $x_5_2 = {50 ff b4 24 ?? ?? ?? ?? ff b4 24 ?? ?? ?? ?? ff 74 24 ?? ff 75 00 68 ?? ?? ?? ?? ff 35}  //weight: 5, accuracy: Low
        $x_1_3 = "\\microsoft\\lsass.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


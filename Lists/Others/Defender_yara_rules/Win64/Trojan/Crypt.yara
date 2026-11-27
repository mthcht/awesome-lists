rule Trojan_Win64_Crypt_SXA_2147948337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Crypt.SXA!MTB"
        threat_id = "2147948337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 c9 0f 57 c9 f3 48 0f 2a c9 f3 41 0f 59 ca 8b c8 c1 e9 ?? 0f b6 c9 0f 57 d2 f3 48 0f 2a d1 f3 41 0f 59 d2 c1 e8 ?? 0f 57 db f3 48 0f 2a d8 f3 41 0f 59 da}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8b 14 13 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8d 84 24 80 00 00 00 48 89 44 24 20 41 b9 ?? ?? ?? ?? 4c 8b c7 48 8b 54 24 30 48 8b 14 13 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff c6 48 8d 5b 08 48 8b 4c 24 38 4c 8b 54 24 30 49 2b ca 48 c1 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Crypt_NMX_2147982923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Crypt.NMX!MTB"
        threat_id = "2147982923"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinSvcGuard" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "\\svc%06X.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


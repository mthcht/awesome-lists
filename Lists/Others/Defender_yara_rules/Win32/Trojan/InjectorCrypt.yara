rule Trojan_Win32_InjectorCrypt_SK_2147755584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InjectorCrypt.SK!MTB"
        threat_id = "2147755584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InjectorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 5e 5b c9 c2 0c 00 80 00 55 89 e5 83 ec 28 53 56 57 01 db 8b 75 08 43 89 f7 11 d9 eb [0-5] 8b 5d 10 87 d1 83 7d 0c 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5e 5b c9 c2 0c 00 50 00 09 d9 ac 6b d2 ?? eb [0-5] 31 d8 0f af d0 aa 01 55 fc eb [0-5] 1f c1 c3 [0-4] 89 c1 eb [0-5] 03 5d 10 2d [0-4] ff 4d 0c f7 d9 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InjectorCrypt_SL_2147772847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InjectorCrypt.SL!MTB"
        threat_id = "2147772847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InjectorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 00 89 45 ?? 83 7d ?? 00 74 02 eb 02 eb ?? 6a 00 6a 01 8b 45 ?? ff 70 ?? ff 55 ?? 83 45 ?? 04 eb ?? c9 c3}  //weight: 2, accuracy: Low
        $x_2_2 = {58 50 83 e8 ?? c3 8b 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? c9 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InjectorCrypt_SN_2147773605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InjectorCrypt.SN!MTB"
        threat_id = "2147773605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InjectorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 d0 8b 55 ?? 8b 52 ?? 29 d0 8b 55 ?? 8b 52 ?? 8d 04 10 89 45 ?? 8b 55 ?? 8b 45 ?? b1 00 ff 55 ?? c9 c3}  //weight: 2, accuracy: Low
        $x_2_2 = {89 f6 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 00 89 02 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 40 04 89 42 04 83 85 ?? ?? ?? ?? 08 83 85 ?? ?? ?? ?? 08 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 73}  //weight: 2, accuracy: Low
        $x_2_3 = {55 89 e5 8d 64 24 ?? 50 e8 00 00 00 00 58 83 c0 ?? 89 45 ?? 58 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 8b 00 89 45 ?? 8b 45 ?? 8b 40 04 89 45 ?? 8b 45 ?? 8d 40 08 89 45 ?? 6a 40 68 00 30 00 00 ff 75 ?? 6a 00 ff 55}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


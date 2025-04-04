rule Trojan_Win32_SpyVoltar_PACN_2147900456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyVoltar.PACN!MTB"
        threat_id = "2147900456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyVoltar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d0 29 d0 b9 0a 00 00 00 31 db 31 d2 f7 f1 83 c2 30 88 14 1c 43 85 c0 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {68 bd 01 00 00 68 bd 01 00 00 6a 22 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyVoltar_ASV_2147916951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyVoltar.ASV!MTB"
        threat_id = "2147916951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyVoltar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 71 ff 8a 11 66 33 54 45 84 66 c1 c2 08 66 89 14 47 40 3b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyVoltar_EM_2147917648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyVoltar.EM!MTB"
        threat_id = "2147917648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyVoltar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\system32\\gbdwpbm.dll" ascii //weight: 1
        $x_1_2 = "begun.ru/click.jsp?url=" ascii //weight: 1
        $x_1_3 = "_blank" ascii //weight: 1
        $x_1_4 = "ow5dirasuek.com" ascii //weight: 1
        $x_1_5 = "mkkuei4kdsz.com" ascii //weight: 1
        $x_1_6 = "lousta.net" ascii //weight: 1
        $x_1_7 = "%SystemRoot%\\System32\\omsecor.exe" ascii //weight: 1
        $x_1_8 = "%APPDATA%\\omsecor.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyVoltar_KAA_2147937898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyVoltar.KAA!MTB"
        threat_id = "2147937898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyVoltar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {99 b9 e8 03 00 00 f7 f9 8b f2 81 c6 c8}  //weight: 2, accuracy: High
        $x_2_2 = {99 b9 b0 04 00 00 f7 f9 83 c2 64}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


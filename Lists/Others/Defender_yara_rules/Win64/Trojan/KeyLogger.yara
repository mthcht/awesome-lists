rule Trojan_Win64_KeyLogger_DB_2147828897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KeyLogger.DB!MTB"
        threat_id = "2147828897"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {f6 54 0d b0 48 ff c1 48 83 f9 1b 72 f3 4c 8d 45 b0}  //weight: 3, accuracy: High
        $x_2_2 = {0f b7 01 41 b9 ff ff 00 00 66 f7 d0 66 41 89 04 08 0f b7 01 48 8d 49 02 66 44 3b c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KeyLogger_NK_2147927972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KeyLogger.NK!MTB"
        threat_id = "2147927972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {49 01 d0 4c 89 f2 4c 89 45 ?? 41 b8 02 00 00 00 e8 21 fc ff ff e9 e0 fe ff ff 48 8d 0d 3d e8 0a 00 48 c7 45 ?? 00 00 00 00 e8 98 fb ff ff}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8b 10 48 8d 4c 24 ?? 4c 8d 4c 24 ?? 41 b8 10 00 00 00 e8 2b 8f ff ff 85 c0 7e 17 0f b7 4c 24 ?? 66 89 4b 18 89 43 14 eb ab}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KeyLogger_NK_2147927972_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KeyLogger.NK!MTB"
        threat_id = "2147927972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 44 24 48 41 b9 01 00 00 00 48 89 44 24 20 48 8d 15 7c 68 00 00 48 8b c3 45 33 c0 48 c7 c1 02 00 00 80 ff 15 89 f2 00 00 85 c0 74 37}  //weight: 2, accuracy: High
        $x_1_2 = {c7 44 24 40 08 02 00 00 48 89 44 24 20 48 8d 15 91 68 00 00 48 8b c6 45 33 c0 ff 15 15 f2 00 00 48 8b 4c 24 48 8b d8 49 8b c6 ff 15 05 f2 00 00 48 8b cf}  //weight: 1, accuracy: High
        $x_1_3 = "keylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KeyLogger_NK_2147927972_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KeyLogger.NK!MTB"
        threat_id = "2147927972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Windows Atapi x86_64 Driver" ascii //weight: 2
        $x_2_2 = "hacks.txt" wide //weight: 2
        $x_1_3 = "Chave aberta com sucesso" ascii //weight: 1
        $x_1_4 = "Erro ao obter o nome do usu" ascii //weight: 1
        $x_1_5 = "InternetConnectW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


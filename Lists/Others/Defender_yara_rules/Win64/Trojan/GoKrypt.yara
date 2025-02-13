rule Trojan_Win64_GoKrypt_DW_2147888221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoKrypt.DW!MTB"
        threat_id = "2147888221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 ed 30 9e 20 2a dc 17 a9 1c 6c 9f c5 99 bf 62 28 33 71 78 1a 79 be 97 66 f2 1c 7a 70 db 30 52 96 65 1d 95 52 27 16}  //weight: 1, accuracy: High
        $x_1_2 = {08 0a 20 f1 c0 11 8a 15 7c b4 b9 d4 8b 3f 1d 31 7c 08 d5 1d 4a 40 ed 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoKrypt_AB_2147893964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoKrypt.AB!MTB"
        threat_id = "2147893964"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID:" ascii //weight: 2
        $x_2_2 = "gwMDEwMDAwMDQxYjk0MDAwMDAwMDQxYmE1OGE0NTNlNWZmZDU0ODkzNTM1MzQ4ODllNzQ4ODl" ascii //weight: 2
        $x_2_3 = "mMTQ4ODlkYTQxYjgwMDIwMDAwMDQ5ODlmOTQxYmExMjk2ODllMmZmZDU0ODgzYzQyMDg1YzA3NGI2NjY4Y" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoKrypt_AC_2147895113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoKrypt.AC!MTB"
        threat_id = "2147895113"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID:" ascii //weight: 2
        $x_2_2 = "TcyAkqh4oJXgV3WYyL4KEfCMk9W8oJCpmx1bo+jVgKY=" ascii //weight: 2
        $x_2_3 = "UDRbotTOMtkuf7TTJQPiSVjdRZqUmi1oGe5fUs2hLww=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoKrypt_AC_2147895113_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoKrypt.AC!MTB"
        threat_id = "2147895113"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e7 fc f3 48 a5 48 89 e6 48 8b 0e 48 8b 56 08 4c 8b 46 10 4c 8b 4e 18 66 48 0f 6e c1 66 48 0f 6e ca 66 49 0f 6e d0 66 49 0f 6e d9 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = "Go buildinf:" ascii //weight: 1
        $x_1_3 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ascii //weight: 1
        $x_1_4 = "HjMWZ4y6kC.kLyjAIXkYa9k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


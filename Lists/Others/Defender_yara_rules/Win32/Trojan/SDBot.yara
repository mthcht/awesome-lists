rule Trojan_Win32_SDBot_PABJ_2147893429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SDBot.PABJ!MTB"
        threat_id = "2147893429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SDBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ad fc ff ff ff ab b6 72 6b 8b 1f 81 b5 f4 ff ff ff d2 99 ef 9b 03 de 81 b5 fc ff ff ff 9c ca d8 7a 89 1a 81 ad f0 ff ff ff a0 74 70 6e 81 c2 26 69 cf 77 81 c2 de 96 30 88 81 c7 04 00 00 00 e2 be}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SDBot_PABL_2147893523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SDBot.PABL!MTB"
        threat_id = "2147893523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SDBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ad ec ff ff ff 2e ff a4 91 8b 3b 81 85 d8 ff ff ff 8e 6b bb ba 33 fe 81 85 d8 ff ff ff e8 e0 20 49 89 3a 81 c2 83 fa d8 b6 81 ea 7f fa d8 b6 81 c3 ad 98 ab 0d 81 eb a9 98 ab 0d e2 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SDBot_PABM_2147893852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SDBot.PABM!MTB"
        threat_id = "2147893852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SDBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 17 81 b5 ec ff ff ff 0c 1c 7f e5 03 d3 29 9d e0 ff ff ff 89 16 31 95 c8 ff ff ff 81 c6 04 00 00 00 81 c7 28 d2 bb e7 81 ef 24 d2 bb e7 e2 d0}  //weight: 5, accuracy: High
        $x_5_2 = {01 95 f0 ff ff ff 8b 3a 01 85 f4 ff ff ff 2b fb 01 bd f4 ff ff ff 89 3e 29 9d fc ff ff ff 81 c6 04 00 00 00 81 c2 04 00 00 00 e2 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


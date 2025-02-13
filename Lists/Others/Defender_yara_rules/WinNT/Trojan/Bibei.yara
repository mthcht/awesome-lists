rule Trojan_WinNT_Bibei_A_2147651605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bibei.A"
        threat_id = "2147651605"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bibei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 03 00 00 80 79 ?? 48 83 c8 fc 40 89 45 fc 8b 45 10 99 b9 ff 00 00 00 f7 f9 88 55 ef 8b 55 08 89 55 f4 c7 45 f8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 55 f0 a1 ?? ?? ?? ?? 8b 08 8b 14 91 89 15 ?? ?? ?? ?? fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 0f b7 45 f0 8b 0d ?? ?? ?? ?? 8b 11 c7 04 82 ?? ?? ?? ?? 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Bibei_B_2147651628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bibei.B"
        threat_id = "2147651628"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bibei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f8 c7 45 f4 12 02 00 00 6a 00 8b 4d f8}  //weight: 1, accuracy: High
        $x_1_2 = {eb 02 eb ab [0-31] 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


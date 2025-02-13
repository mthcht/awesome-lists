rule Trojan_WinNT_Necurs_A_162163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Necurs.A"
        threat_id = "162163"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Necurs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 de c0 ad de 39 46 04 0f 85 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4e 08 33 0e 3b c8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 65 fc 00 8b 75 fc 8b 4d 08 8b 45 f8 f7 de 1b f6 81 e6 f3 ff ff 3f 81 c6 0d 00 00 c0 32 d2 89 71 18 89 41 1c ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


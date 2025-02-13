rule Trojan_WinNT_Hesock_A_2147659605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Hesock.A"
        threat_id = "2147659605"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Hesock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7b 10 01 74 ?? 83 7d 10 00 7c ?? 8b 43 14 2d 05 01 01 00 74 ?? 83 e8 09 74 ?? 83 e8 06 74 ?? 2d ee ff ff 00 75 ?? 8b 4b 1c 56 8b 73 18 57 8b 7d 08 8b c1 83 c7 53 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 51 04 0f b7 c6 03 c7 30 10 8a 51 04 30 50 01 46 46 66 3b 71 10 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


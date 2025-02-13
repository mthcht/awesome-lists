rule Trojan_WinNT_Rortiem_A_2147658139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Rortiem.A"
        threat_id = "2147658139"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Rortiem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 31 8b 4d 10 8b 5d 0c 33 ff 8d 51 04 39 02 75 05 80 3b b8 74 0b 47 83 c2 04 83 ff 0f 7c ee eb ?? 8d 04 bd ?? ?? ?? ?? 83 38 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 cf 51 8b 4d 08 8b 04 88 03 c7 50 ff 55 0c 85 c0 74 11 8b 45 ?? ff 45 08 8b 4d 08 3b 4e 18 8b 55 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


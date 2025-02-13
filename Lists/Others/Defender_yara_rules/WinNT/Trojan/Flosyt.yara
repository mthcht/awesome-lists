rule Trojan_WinNT_Flosyt_A_2147650256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Flosyt.A"
        threat_id = "2147650256"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Flosyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 08 8b 00 8b 15 ?? ?? ?? ?? 3b 54 88 fc 74 04 e2 f8 eb 0f 8d 44 88 fc a3 ?? ?? ?? ?? c7 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7c 24 04 05 75 0e 8b 74 24 08 8b 3c 24 c7 04 24 ?? ?? ?? ?? ff 25 ?? ?? ?? ?? 85 c0 75 ?? eb ?? 03 36 39 46 3c 74 ?? 8b 56 3c 81 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


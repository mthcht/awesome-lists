rule Trojan_WinNT_Chon_A_2147614396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Chon.gen!A"
        threat_id = "2147614396"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Chon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 7d 0c 8b 45 08 8a 04 02 32 01 32 45 14 46 3b 75 14 88 01 7c e1}  //weight: 1, accuracy: High
        $x_1_2 = {0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 58 8b 45 08 8b 4d fc 89 08}  //weight: 1, accuracy: High
        $x_1_3 = {83 4d f4 ff 33 ?? c7 45 f0 00 1f 0a fa 33 [0-8] 75 12 8d 45 f0 50 ?? ?? ff 15 ?? ?? 01 00 ?? 83 ?? 1e 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


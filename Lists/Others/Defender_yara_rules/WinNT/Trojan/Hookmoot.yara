rule Trojan_WinNT_Hookmoot_A_2147626477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Hookmoot.gen!A"
        threat_id = "2147626477"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Hookmoot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 40 01 8b 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 09 8b 04 81 a3 ?? ?? ?? ?? 8d 45 ?? 50 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {50 0f 20 c0 a3 ?? ?? ?? ?? 25 ff ff fe ff 0f 22 c0 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


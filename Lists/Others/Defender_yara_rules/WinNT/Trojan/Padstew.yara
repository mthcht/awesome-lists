rule Trojan_WinNT_Padstew_A_2147626420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Padstew.A"
        threat_id = "2147626420"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Padstew"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 8b 55 f8 8b 45 f4 8b 00 89 04 8a 0f 20 c0}  //weight: 1, accuracy: High
        $x_1_2 = {b9 1b 00 00 00 c7 44 88 34 ?? ?? 40 00 49 75 f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


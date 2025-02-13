rule Trojan_WinNT_Simda_A_2147650329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Simda.gen!A"
        threat_id = "2147650329"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4e 3c 03 ce 0f b7 51 14 57 0f b7 79 06 8d 54 0a 18 8b cf 2b ce 8d 4c 11 28}  //weight: 1, accuracy: High
        $x_1_2 = "c_%4.4x%d.nls" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Simda_B_2147650678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Simda.gen!B"
        threat_id = "2147650678"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 3a 10 75 ?? 47 40 3b fe 72 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 41 9f 66 83 f8 19 77 ?? 81 c1 e0 ff 00 00 eb ?? 0f b7 c9}  //weight: 1, accuracy: Low
        $x_1_3 = "ModuleR0Pdm" ascii //weight: 1
        $x_1_4 = {41 6d 65 72 69 63 61 20 4f 6e 6c 69 6e 65 20 42 72 6f 77 73 65 72 20 31 2e 31 00 00 3f 4f 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


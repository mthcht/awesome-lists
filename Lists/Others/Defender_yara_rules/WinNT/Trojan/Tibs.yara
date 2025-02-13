rule Trojan_WinNT_Tibs_A_2147597707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Tibs.gen!A"
        threat_id = "2147597707"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3a 6e 64 69 73 74 08 81 3a 4e 44 49 53 75 07 e8 0c 00 00 00 eb 05 e8 ?? ?? ff ff ab eb c8 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Tibs_D_2147633340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Tibs.gen!D"
        threat_id = "2147633340"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 83 c4 04 52 c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f 20 c6 89 f7 0f ba fe 10 0f 22 c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


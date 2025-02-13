rule Spammer_WinNT_Srizbi_A_2147605320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:WinNT/Srizbi.A"
        threat_id = "2147605320"
        type = "Spammer"
        platform = "WinNT: WinNT"
        family = "Srizbi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d6 84 c0 74 1f 8d 7b 38 57 ff d6 84 c0 74 15 81 3f ef be ad de 75 0d 68}  //weight: 1, accuracy: High
        $x_1_2 = {7c ed 89 10 8d 50 08 89 16 2b f8 83 ef 14 c6 02 58 8b 10 41 89 70 04 c6 40 09 68 89 50 0a c6 40 0e 50 c6 40 0f e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


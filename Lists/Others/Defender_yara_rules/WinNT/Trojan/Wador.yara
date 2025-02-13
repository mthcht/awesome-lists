rule Trojan_WinNT_Wador_A_2147649314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Wador.A"
        threat_id = "2147649314"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Wador"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 24 40 41 57 75 09 81 78 04 44 46 4c 41 74}  //weight: 1, accuracy: High
        $x_1_2 = {bd 49 4d 53 24 ee e6 eb e6 eb e6 eb e6 eb e6 eb}  //weight: 1, accuracy: High
        $x_1_3 = {3d 80 21 10 80 74 ?? 3d 84 21 10 80 74 ?? 3d 88 21 10 80 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_WinNT_Kapa_A_2147633596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Kapa.A"
        threat_id = "2147633596"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Kapa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 8b ff 55 8b 75 ?? 81 78 04 ec 56 64 a1 75 ?? 81 78 08 24 01 00 00 75 ?? 81 78 0c 8b 75 08 3b 74}  //weight: 1, accuracy: Low
        $x_1_2 = "NtQuerySystemInformation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


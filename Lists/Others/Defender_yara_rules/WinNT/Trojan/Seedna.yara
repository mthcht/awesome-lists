rule Trojan_WinNT_Seedna_A_2147685293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Seedna.A"
        threat_id = "2147685293"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Seedna"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\DosDevices\\{E07DB02C-387E-43b2-A6F2-C59B4934B7D6" wide //weight: 2
        $x_2_2 = {53 45 45 44 2e 53 59 53 00 49 6f 70 51 75 65 72 79 49 6e 74 65 72 66 61 63 65 00 49 6f 70 52 65 67 69 73 74 65 72 49 6e 74 65 72 66 61 63 65}  //weight: 2, accuracy: High
        $x_2_3 = {57 68 44 52 56 4d 50 6a 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_WinNT_Parchood_A_2147647957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Parchood.A"
        threat_id = "2147647957"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Parchood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0e c7 05 09 00 ff ff ff d0 3d 0b 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {e4 50 8d 05 0f 00 6a 00 6a 00 8d 45 e8 50 68 ff 03 1f 00 8d 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


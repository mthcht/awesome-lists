rule Trojan_WinNT_Worbe_A_2147610829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Worbe.A"
        threat_id = "2147610829"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Worbe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0c 56 ff 75 08 ff 15 ?? ?? 01 00 eb 05 b8 22 00 00 c0 8b 4d fc 5f 5e e8}  //weight: 1, accuracy: Low
        $x_1_2 = "msdefender" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


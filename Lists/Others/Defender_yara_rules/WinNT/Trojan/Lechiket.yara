rule Trojan_WinNT_Lechiket_A_2147658193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Lechiket.A"
        threat_id = "2147658193"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Lechiket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GET /%s?&id=%s&mark=%s" ascii //weight: 1
        $x_1_2 = "srv.php" ascii //weight: 1
        $x_1_3 = "[NETWORK DATA:]" ascii //weight: 1
        $x_1_4 = "SERVERISOK" ascii //weight: 1
        $x_1_5 = {80 c2 61 88 14 0e 46 83 fe 08 72 e2 c6 04 0e 00 b8 23 34 22 00 8b f9 4f f6 c3 01 74 0f 8a 47 01 47 84 c0 75 f8 be ?? ?? ?? ?? eb 0d 8a 47 01 47 84 c0 75 f8 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


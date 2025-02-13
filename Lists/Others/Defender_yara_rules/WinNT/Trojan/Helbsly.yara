rule Trojan_WinNT_Helbsly_A_2147603164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Helbsly.A"
        threat_id = "2147603164"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Helbsly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 39 5d d8 76 50 66 81 7d d8 ff 00 73 48 8b 46 44 3b 05 ?? ?? ?? ?? 75 75 8b 46 28}  //weight: 1, accuracy: Low
        $x_1_2 = {74 09 81 7d 1c 03 00 12 00 74 07 8b c7 e9 48 01 00 00 85 ff 0f 8c 3d 01 00 00 83 65 d0 00 6a 05 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


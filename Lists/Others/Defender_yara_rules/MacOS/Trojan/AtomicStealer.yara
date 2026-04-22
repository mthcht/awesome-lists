rule Trojan_MacOS_AtomicStealer_K_2147967465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AtomicStealer.K!AMTB"
        threat_id = "2147967465"
        type = "Trojan"
        platform = "MacOS: "
        family = "AtomicStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 04 b0 41 0f b6 f8 89 c1 80 e1 07 d3 ef f6 d8 24 07 89 c1 41 d3 e0 f6 03 01 48 89 d0 74 9c 48 8b 43 10 eb 96}  //weight: 3, accuracy: High
        $x_3_2 = {d3 ef f6 d8 24 07 89 c1 41 d3 e0 f6 03 01 48 89 d0 74 9c 48 8b 43 10 eb 96}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


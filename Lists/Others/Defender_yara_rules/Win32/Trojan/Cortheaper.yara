rule Trojan_Win32_Cortheaper_A_2147642807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cortheaper.A"
        threat_id = "2147642807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cortheaper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ad_search.htm?pid=" wide //weight: 1
        $x_1_2 = "search_auction.htm?at_topsearch=" wide //weight: 1
        $x_2_3 = {6f 00 6d 00 34 00 68 00 67 00 6f 00 64 00 74 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 34 00 30 00 2d 00 2d 00 63 00 6f 00 6d 00 6d 00 65 00 6e 00 64 00 2d 00 30 00 2d 00 61 00 6c 00 6c 00 2d 00 30 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = "rer\\VIEW SOURCE EDITOR\\EDITOR NAME" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


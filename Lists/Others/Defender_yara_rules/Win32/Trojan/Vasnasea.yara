rule Trojan_Win32_Vasnasea_2147678707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vasnasea"
        threat_id = "2147678707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vasnasea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 75 73 63 6f 63 00 (41|42|43|44|45|46|47|48|49|4a|4b|4c|4d|4e|4f|50|51|52|53|54|55|56|57|58|59|5a) ?? ?? (61|62|63|64|65|66|67|68|69|6a|6b|6c|6d|6e|6f|70|71|72|73|74|75|76|77|78|79|7a) (61|62|63|64|65|66|67|68|69|6a|6b|6c|6d|6e|6f|70|71|72|73|74|75|76|77|78|79|7a) 00 54 62 72 69 7a 00 59 69 6c 6c 71 78 66 76 76 0f 00 ?? ?? ?? ?? ?? ?? ?? ?? (61|62|63|64|65|66|67|68|69|6a|6b|6c|6d|6e|6f|70|71|72|73|74|75|76|77|78|79|7a) (61|62|63|64|65|66|67|68|69|6a|6b|6c|6d|6e|6f|70|71|72|73|74|75|76|77|78|79|7a) 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule PWS_Win32_Codtree_A_2147624310_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Codtree.gen!A"
        threat_id = "2147624310"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Codtree"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 6c 6c 75 42 e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 65 74 75 43 e8}  //weight: 1, accuracy: High
        $x_1_3 = {68 5f 72 61 46 e8}  //weight: 1, accuracy: High
        $x_1_4 = {68 61 6c 5a 46 e8}  //weight: 1, accuracy: High
        $x_1_5 = {68 50 58 46 46 e8}  //weight: 1, accuracy: High
        $x_1_6 = {68 58 70 74 46 e8}  //weight: 1, accuracy: High
        $x_1_7 = {68 74 72 6d 53 e8}  //weight: 1, accuracy: High
        $x_2_8 = {c6 06 0d 46 c6 06 0a 46}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


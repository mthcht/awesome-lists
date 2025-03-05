rule Trojan_Win32_MshtaScriptE_A_2147763459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MshtaScriptE.A"
        threat_id = "2147763459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaScriptE"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00}  //weight: 2, accuracy: Low
        $x_2_2 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00}  //weight: 2, accuracy: Low
        $x_1_3 = ".run" wide //weight: 1
        $x_1_4 = "execute" wide //weight: 1
        $n_2_5 = {44 00 61 00 74 00 61 00 [0-16] 75 00 70 00 64 00 61 00 74 00 65 00 [0-16] 73 00 75 00 63 00 63 00 65 00 65 00 64 00 65 00 64 00}  //weight: -2, accuracy: Low
        $n_2_6 = {72 00 75 00 6e 00 [0-16] 73 00 63 00 63 00 6d 00 [0-16] 75 00 70 00 64 00 61 00 74 00 65 00}  //weight: -2, accuracy: Low
        $n_2_7 = "MsgBox" wide //weight: -2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


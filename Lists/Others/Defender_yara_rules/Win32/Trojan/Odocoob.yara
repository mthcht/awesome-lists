rule Trojan_Win32_Odocoob_D_2147729387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Odocoob.D"
        threat_id = "2147729387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Odocoob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "odbcconf" wide //weight: 10
        $x_1_2 = {7b 00 72 00 65 00 67 00 73 00 76 00 72 00 20 00 [0-6] 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {7b 00 72 00 65 00 67 00 73 00 76 00 72 00 20 00 [0-6] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


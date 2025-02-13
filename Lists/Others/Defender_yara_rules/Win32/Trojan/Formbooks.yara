rule Trojan_Win32_Formbooks_GPX_2147920387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbooks.GPX!MTB"
        threat_id = "2147920387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbooks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 5, accuracy: Low
        $x_1_3 = ".OpenTextFile ( @TEMPDIR & " ascii //weight: 1
        $x_1_4 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 [0-3] 28 00 [0-31] 28 00}  //weight: 1, accuracy: Low
        $x_1_5 = {44 6c 6c 43 61 6c 6c [0-3] 28 [0-31] 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}


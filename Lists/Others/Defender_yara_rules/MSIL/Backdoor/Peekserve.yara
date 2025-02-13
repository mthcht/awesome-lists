rule Backdoor_MSIL_Peekserve_B_2147769096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Peekserve.B!dha"
        threat_id = "2147769096"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Peekserve"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "3af85bb3-fc6d-4545-8136-dd0639ec8d49" ascii //weight: 3
        $x_2_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 [0-32] 2e 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 2e 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_3 = "get_Installers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


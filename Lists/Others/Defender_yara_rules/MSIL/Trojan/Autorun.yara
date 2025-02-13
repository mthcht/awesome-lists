rule Trojan_MSIL_Autorun_J_2147745042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Autorun.J!ibt"
        threat_id = "2147745042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autorun"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 20 00 [0-255] 20 00 20 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 68 00 61 00 72 00 65 00 64 00 20 00 4d 00 75 00 73 00 69 00 63 00 20 00 20 00 20 00 [0-255] 20 00 20 00 20 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\System Recovery\\recmgmt.cmd" wide //weight: 1
        $x_1_4 = "open=KB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Maptrepol_A_2147712217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maptrepol.A"
        threat_id = "2147712217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maptrepol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "n_mttr_ppl_whtss_y_sy" wide //weight: 2
        $x_2_2 = "Wrlck.dll" ascii //weight: 2
        $x_2_3 = "Prst.dll" ascii //weight: 2
        $x_1_4 = "\\starter.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


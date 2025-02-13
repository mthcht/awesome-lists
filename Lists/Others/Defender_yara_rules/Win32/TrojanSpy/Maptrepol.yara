rule TrojanSpy_Win32_Maptrepol_A_2147712219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maptrepol.A"
        threat_id = "2147712219"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maptrepol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "N_e_w__de_ven_ex_key_r_cd_1" wide //weight: 2
        $x_2_2 = "PrstInd.bin" ascii //weight: 2
        $x_2_3 = "\\keylogger.pdb" ascii //weight: 2
        $x_2_4 = "%lsmsattrib32_%s_k_%u.res" ascii //weight: 2
        $x_1_5 = "prst.cab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}


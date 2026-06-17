rule Ransom_Win32_SeroWare_AMTB_2147971770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SeroWare!AMTB"
        threat_id = "2147971770"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SeroWare"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\SeroWare\\obj\\Debug\\SeroWare.pdb" ascii //weight: 4
        $x_1_2 = "SeroWare.Program+<GetAllFiles>" ascii //weight: 1
        $x_1_3 = ".serocrypt" ascii //weight: 1
        $x_1_4 = "SeroWorms" ascii //weight: 1
        $x_1_5 = "DisableCMD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


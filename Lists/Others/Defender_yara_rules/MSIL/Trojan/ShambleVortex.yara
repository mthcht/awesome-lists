rule Trojan_MSIL_ShambleVortex_A_2147959880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShambleVortex.A!dha"
        threat_id = "2147959880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShambleVortex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "connector.bin" wide //weight: 1
        $x_1_2 = "greates_strngth" wide //weight: 1
        $x_1_3 = "binary.conf" wide //weight: 1
        $x_1_4 = "rprepare.vbs" wide //weight: 1
        $x_1_5 = "rclone.vbs" wide //weight: 1
        $x_1_6 = "descritbe_work" wide //weight: 1
        $x_1_7 = "checkBoxConfurmed" wide //weight: 1
        $x_1_8 = "Set file = fso.OpenTextFile(\"python312._pth\", 8, True)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


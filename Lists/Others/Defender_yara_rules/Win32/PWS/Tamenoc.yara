rule PWS_Win32_Tamenoc_A_2147629517_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tamenoc.A"
        threat_id = "2147629517"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tamenoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fb 13 71 20 ff 6c 20 ff ec f4 18 eb b6 fb e7 fc 10 6c 24 ff 04 5c ff fc a0 6c 20 ff f5 18 00 00 00 c2}  //weight: 2, accuracy: High
        $x_2_2 = "E800000000832C24055589E583EC4064A1300000008B400C8B401C8B008B4008" wide //weight: 2
        $x_1_3 = "drowssaP\\CUD\\skrewlatiV\\ERAWTFOS\\ENIHCAM_LACOL_YEKH" wide //weight: 1
        $x_1_4 = "htaPmaetS\\maetS\\evlaV\\erawtfoS\\RESU_TNERRUC_YEKH" wide //weight: 1
        $x_1_5 = "tcejbOmetsySeliF.gnitpircS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


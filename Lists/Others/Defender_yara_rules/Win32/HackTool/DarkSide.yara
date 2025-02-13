rule HackTool_Win32_DarkSide_C_2147780932_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DarkSide.C!dha"
        threat_id = "2147780932"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSide"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "-type" wide //weight: 100
        $x_90_2 = "encryptor" wide //weight: 90
        $x_10_3 = "-release" wide //weight: 10
        $x_10_4 = "-debug" wide //weight: 10
        $x_10_5 = "-dll" wide //weight: 10
        $x_10_6 = "-dlldebug" wide //weight: 10
        $x_100_7 = "decryptor" wide //weight: 100
        $x_100_8 = "decrypt_one" wide //weight: 100
        $x_50_9 = "-config" wide //weight: 50
        $x_50_10 = "-pubkey" wide //weight: 50
        $x_50_11 = "-privkey" wide //weight: 50
        $x_50_12 = "-ofile" wide //weight: 50
        $x_50_13 = "-ifile" wide //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_90_*) and 4 of ($x_50_*) and 1 of ($x_10_*))) or
            ((1 of ($x_90_*) and 5 of ($x_50_*))) or
            ((1 of ($x_100_*) and 4 of ($x_50_*))) or
            ((1 of ($x_100_*) and 1 of ($x_90_*) and 2 of ($x_50_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_90_*) and 3 of ($x_50_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*))) or
            ((2 of ($x_100_*) and 1 of ($x_90_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_90_*) and 1 of ($x_50_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}


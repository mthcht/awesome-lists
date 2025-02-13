rule VirTool_WinNT_Laqma_C_2147598668_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Laqma.C"
        threat_id = "2147598668"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Laqma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 00 3d 93 08 00 00 74 ?? 3d 28 0a 00 00 74 ?? 3d ce 0e 00 00 74}  //weight: 2, accuracy: Low
        $x_2_2 = {fa 0f 20 c0 89 44 24 00 25 ff ff fe ff 0f 22 c0 a1}  //weight: 2, accuracy: High
        $x_2_3 = {8b 44 24 00 0f 22 c0 fb b0 01 59 c3}  //weight: 2, accuracy: High
        $x_1_4 = {eb 08 66 83 38 5c 74 0c 48 48 3b c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Laqma_A_2147598672_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Laqma.A"
        threat_id = "2147598672"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Laqma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 d4 fd ff ff 74 1d 66 83 38 21 75 05 66 c7 00 5c 00 66 83 38 47 75 05 66 c7 00 52 00 40 40 66 39 38}  //weight: 1, accuracy: High
        $x_1_2 = {8d 85 cc fd ff ff 74 1d 66 83 38 21 75 05 66 c7 00 5c 00 66 83 38 47 75 05 66 c7 00 52 00 03 c7 66 39 18}  //weight: 1, accuracy: High
        $x_1_3 = {eb 32 8d 7b 5e be ?? (05|06) 01 00 a5 a5 a5 a5 c7 43 3c 10 00 00 00 fb 83 4d fc ff b8 0f 00 00 c0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


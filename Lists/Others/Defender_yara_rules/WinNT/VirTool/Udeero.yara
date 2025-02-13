rule VirTool_WinNT_Udeero_A_2147683699_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Udeero.A"
        threat_id = "2147683699"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Udeero"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {3d 0c 20 00 80 74 ?? 3d 10 20 00 80 74 0c c7 45 f8 0d 00 00 c0 e9}  //weight: 3, accuracy: Low
        $x_1_2 = "[g_nCurrReplaceDataLen <= 0]" ascii //weight: 1
        $x_1_3 = "[ModifyPacket hook]" ascii //weight: 1
        $x_1_4 = "[GET Io Data]" ascii //weight: 1
        $x_1_5 = "[goto Refelse]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule VirTool_WinNT_Hyflid_A_2147608689_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hyflid.A"
        threat_id = "2147608689"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hyflid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 4c 6a 00 e8 ?? ?? 00 00 0b c0 0f 84 ?? 00 00 00 a3 ?? ?? 01 00 6a 00 68 4b 53 70 79 6a 10 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {59 c9 c2 04 00 fa 50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 c3 50 0f 20 c0 0d 00 00 01 00 0f 22 c0 58 fb c3 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


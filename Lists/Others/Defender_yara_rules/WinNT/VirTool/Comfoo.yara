rule VirTool_WinNT_Comfoo_A_2147643784_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Comfoo.A"
        threat_id = "2147643784"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Comfoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 83 e8 05 89 45 08 a1 ?? ?? ?? ?? c6 00 e9 40 52 8b 55 08 89 10 5a 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Device\\DevCtrlKrnl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win32_ObfusPowershellExec_A_2147958102_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ObfusPowershellExec.A"
        threat_id = "2147958102"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ObfusPowershellExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pow\"e\"r\"s\"hell\".\"e\"x\"e" wide //weight: 1
        $x_1_2 = "p\"o\"wer^s^hell\".\"ex^e" wide //weight: 1
        $x_1_3 = "power^s^hell.ex^e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


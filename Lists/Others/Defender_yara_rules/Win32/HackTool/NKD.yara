rule HackTool_Win32_NKD_A_2147642141_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NKD.A"
        threat_id = "2147642141"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NKD"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nkd.astalavista.ms" ascii //weight: 1
        $x_1_2 = "KEY_EXPLOIT =>" ascii //weight: 1
        $x_1_3 = "El Crabe & TeaM NKD" ascii //weight: 1
        $x_1_4 = "://ElCrabe.BlogSpot." ascii //weight: 1
        $x_1_5 = "lic60.ppl" ascii //weight: 1
        $x_1_6 = "hint_nop" ascii //weight: 1
        $x_1_7 = "-style lic loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


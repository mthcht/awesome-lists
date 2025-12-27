rule HackTool_Win32_Greedy_AMTB_2147956009_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Greedy!AMTB"
        threat_id = "2147956009"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Greedy"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Dump" ascii //weight: 1
        $x_1_2 = "Port" ascii //weight: 1
        $x_2_3 = "main.(*AutoInjector).createPayloadDLL" ascii //weight: 2
        $x_2_4 = "main.scanBrowserData" ascii //weight: 2
        $x_2_5 = "main.exfiltrateResults" ascii //weight: 2
        $x_4_6 = "github.com/moond4rk/hackbrowserdata" ascii //weight: 4
        $x_4_7 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 [0-16] 42 00 6f 00 6f 00 6b 00 6d 00 61 00 72 00 6b 00 [0-16] 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 4, accuracy: Low
        $x_4_8 = {50 61 73 73 77 6f 72 64 [0-16] 42 6f 6f 6b 6d 61 72 6b [0-16] 44 6f 77 6e 6c 6f 61 64}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


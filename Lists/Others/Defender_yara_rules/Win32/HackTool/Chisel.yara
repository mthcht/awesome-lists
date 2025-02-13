rule HackTool_Win32_Chisel_A_2147778169_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Chisel.A"
        threat_id = "2147778169"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Chisel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 68 69 73 65 6c 2d 76 ?? 2d 63 6c 69 65 6e 74}  //weight: 2, accuracy: Low
        $x_1_2 = "chiselclientclosed" ascii //weight: 1
        $x_1_3 = "chisel-chunkedcommand" ascii //weight: 1
        $x_1_4 = "sendchisel" ascii //weight: 1
        $x_1_5 = "CHISEL_KEY" ascii //weight: 1
        $x_1_6 = "chisel.pid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Chisel_B_2147781462_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Chisel.B"
        threat_id = "2147781462"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Chisel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 68 69 73 65 6c 2d 76 ?? 2d 63 6c 69 65 6e 74}  //weight: 2, accuracy: Low
        $x_1_2 = "chiselclientclosed" ascii //weight: 1
        $x_1_3 = "sendchisel" ascii //weight: 1
        $x_1_4 = "CHISEL_KEY" ascii //weight: 1
        $x_1_5 = "invalidlookup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


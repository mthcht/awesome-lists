rule Backdoor_Win64_MantiKing_A_2147972924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/MantiKing.A!dha"
        threat_id = "2147972924"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "MantiKing"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/agent/execute" wide //weight: 1
        $x_1_2 = "-WindowStyle Hidden -ExecutionPolicy Bypass -File " ascii //weight: 1
        $x_1_3 = "\"command\":\"wait\"" ascii //weight: 1
        $x_1_4 = "\"command\":\"delete\"" ascii //weight: 1
        $x_1_5 = "\"command\":\"execute\"" ascii //weight: 1
        $x_1_6 = "C:\\ProgramData\\ManticoraSoftware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


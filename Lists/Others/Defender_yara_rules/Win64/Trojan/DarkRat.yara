rule Trojan_Win64_DarkRat_PA_2147760491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkRat.PA!MSR"
        threat_id = "2147760491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkRat"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DarkVision RAT" wide //weight: 1
        $x_1_2 = "HookProcedure_HookLoader" ascii //weight: 1
        $x_1_3 = "DARKVISIONSERVER64.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


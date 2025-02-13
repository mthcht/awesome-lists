rule Backdoor_Win32_Evelter_A_2147743405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Evelter.A!MSR"
        threat_id = "2147743405"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Evelter"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\Devel\\WinHexCalc-master\\Release\\hexcalc.pdb" ascii //weight: 1
        $x_1_2 = "/OiJAAAAYInlMdJki1Iwi1IMi1IUi3IoD7dKJjH/McCsPGF8Aiwgwc8NAcfi8FJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


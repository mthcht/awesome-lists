rule Backdoor_Win32_Plephij_A_2147903116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plephij.A!dha"
        threat_id = "2147903116"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plephij"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Hijackdll|Set COM Startup with %s" wide //weight: 2
        $x_2_2 = "Hijackdll|Set REG Startup with %s" wide //weight: 2
        $x_2_3 = "Hijackdll|Set Service Startup with %s" wide //weight: 2
        $x_1_4 = "OllyDBG.EXE" wide //weight: 1
        $x_1_5 = "Ida.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


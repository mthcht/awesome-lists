rule Ransom_Win32_Zorro_AA_2147853418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zorro.AA!MTB"
        threat_id = "2147853418"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zorro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_2 = ".zorro" wide //weight: 1
        $x_1_3 = "Zorro.Resources" wide //weight: 1
        $x_1_4 = "\\Ransomware\\zorro\\Zorro\\Zorro\\obj\\Release\\Zorro.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


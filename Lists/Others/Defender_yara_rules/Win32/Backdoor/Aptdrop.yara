rule Backdoor_Win32_Aptdrop_I_2147731969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Aptdrop.I!dha"
        threat_id = "2147731969"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "psisrndrx.ebd" wide //weight: 1
        $x_1_2 = "G:\\Work\\Bison\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


rule Backdoor_Win32_Choopla_D_2147746178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Choopla.D!dha"
        threat_id = "2147746178"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Choopla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "A_Get_LocalDirectory_and_AllDirves" ascii //weight: 3
        $x_2_2 = "H_CopyFile" ascii //weight: 2
        $x_2_3 = "G_UploadFile" ascii //weight: 2
        $x_2_4 = "J_CreateDirectory" ascii //weight: 2
        $x_1_5 = "SELECT [name] FROM master.dbo.sysdatabases ORDER BY 1" ascii //weight: 1
        $x_1_6 = "CopyFile_And_Directory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


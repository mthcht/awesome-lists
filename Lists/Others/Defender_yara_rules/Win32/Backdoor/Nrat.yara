rule Backdoor_Win32_Nrat_A_2147731991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nrat.A"
        threat_id = "2147731991"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyTmpFile.Dat" wide //weight: 1
        $x_1_2 = "C:\\Users\\hoogle168\\Desktop\\2008Projects\\NewCoreCtrl08\\Release\\NewCoreCtrl08.pdb" ascii //weight: 1
        $x_1_3 = "ProcessTrans" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


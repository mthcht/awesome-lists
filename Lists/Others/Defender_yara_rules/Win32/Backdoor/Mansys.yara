rule Backdoor_Win32_Mansys_2147627364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mansys"
        threat_id = "2147627364"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mansys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 72 76 69 63 65 4d 61 69 6e 00 53 74 61 72 74 4c 6f 6f 70 52 75 6e 44 6f 6f 72}  //weight: 1, accuracy: High
        $x_1_2 = "CreateMutexA" ascii //weight: 1
        $x_1_3 = "CreateThread" ascii //weight: 1
        $x_1_4 = "SysMgr\\Loader\\Release\\Loader.pdb" ascii //weight: 1
        $x_1_5 = "Global\\runsingleobject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


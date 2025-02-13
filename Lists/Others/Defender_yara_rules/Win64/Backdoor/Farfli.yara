rule Backdoor_Win64_Farfli_BX_2147816722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Farfli.BX!MTB"
        threat_id = "2147816722"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7zz.exe" ascii //weight: 1
        $x_1_2 = "\\ProgramData\\360.dll" ascii //weight: 1
        $x_1_3 = "ProgramData\\rundll3222.exe" ascii //weight: 1
        $x_1_4 = "\\ProgramData\\svchost.txt" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile" ascii //weight: 1
        $x_1_7 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


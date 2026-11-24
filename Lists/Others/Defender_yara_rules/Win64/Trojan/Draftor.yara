rule Trojan_Win64_Draftor_AN_2147982625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Draftor.AN!MTB"
        threat_id = "2147982625"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Draftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Classes\\CLSID\\{89565275-A714-4a43-912E-978B935EDCCC}\\InprocServer32" ascii //weight: 1
        $x_1_2 = "Microsoft.NET\\Framework\\v4.0.30319\\cvtres.exe" ascii //weight: 1
        $x_1_3 = "6explorer.exe" ascii //weight: 1
        $x_1_4 = "svchost.exe" ascii //weight: 1
        $x_1_5 = "redteam1337/project_notes/main/readme.md" ascii //weight: 1
        $x_2_6 = {c1 e0 05 89 c2 8b 45 fc 01 c2 0f b7 45 f8 0f b6 c0 31 d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


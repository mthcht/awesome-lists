rule Ransom_Win32_Foreign_GJT_2147849395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Foreign.GJT!MTB"
        threat_id = "2147849395"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Foreign"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Roaming\\Microsoft\\Office\\MicrosoftH.exe" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "\\Z_PC\\source\\repos\\Repos\\Release\\normall.pdb" ascii //weight: 1
        $x_1_4 = ".rdata$voltmd" ascii //weight: 1
        $x_1_5 = ".rdata$zzzdbg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


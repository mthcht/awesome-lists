rule HackTool_Win32_Orditti_A_2147653975_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Orditti.A"
        threat_id = "2147653975"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Orditti"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lords Virus Gen " wide //weight: 1
        $x_1_2 = "taskkill /im McSACore.exe /F" wide //weight: 1
        $x_1_3 = "Made By LordTittiS3000" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


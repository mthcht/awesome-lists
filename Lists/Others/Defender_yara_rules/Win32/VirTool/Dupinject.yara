rule VirTool_Win32_Dupinject_A_2147633514_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dupinject.A"
        threat_id = "2147633514"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dupinject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "taskkill /im explorer.exe /f" ascii //weight: 1
        $x_1_2 = "CLSID\\{35CEC8A3-2BE6-11D2-8773-92E220524153}\\InProcServer32" ascii //weight: 1
        $x_1_3 = {6a 00 6a 20 6a 01 6a 00 6a 03 68 00 00 00 c0 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


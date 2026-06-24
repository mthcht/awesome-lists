rule TrojanDropper_Win64_Zusy_SX_2147972210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Zusy.SX!MTB"
        threat_id = "2147972210"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "vixy_sideload_proxy.dll" ascii //weight: 30
        $x_10_2 = "if not exist \"%%BD%%\\VixyMenu.dll\" if not exist \"%%BD%%\\winmm.dll\" goto :done" ascii //weight: 10
        $x_10_3 = "del /f /q \"%%BD%%\\VixyMenu.dll\" >nul 2>" ascii //weight: 10
        $x_10_4 = "del /f /q \"%%BD%%\\winmm_orig.dll\" >nul 2>" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


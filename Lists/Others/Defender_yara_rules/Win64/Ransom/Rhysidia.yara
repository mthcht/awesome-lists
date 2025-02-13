rule Ransom_Win64_Rhysidia_D_2147903965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rhysidia.D!dha"
        threat_id = "2147903965"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhysidia"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rhysida" ascii //weight: 1
        $x_1_2 = "CriticalBreachDetected.pdf" ascii //weight: 1
        $x_1_3 = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\" /v NoChangingWallPaper /t REG_SZ /d 1 /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_LBTWizBackdoor_2147761922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LBTWizBackdoor!ibt"
        threat_id = "2147761922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LBTWizBackdoor"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\LBTWIZ_GLOBAL_STOP" ascii //weight: 1
        $x_1_2 = "Sources\\LBTServ\\LBTWiz\\Release\\Win32\\LBTWiz.pdb" ascii //weight: 1
        $x_1_3 = "\"cmd.exe\" /c schtasks /delete /tn \"Cofax\" /f" ascii //weight: 1
        $x_1_4 = "cmd.exe /c schtasks /create /sc minute /mo 10 /tn \"%s\" /tr \"%s\"" ascii //weight: 1
        $x_1_5 = "/ru \"system\"" ascii //weight: 1
        $x_1_6 = "cmd.exe /c schtasks /delete /tn \"%s\" /f" ascii //weight: 1
        $x_1_7 = "Cofax" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


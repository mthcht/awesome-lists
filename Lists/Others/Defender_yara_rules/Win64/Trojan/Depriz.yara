rule Trojan_Win64_Depriz_G_2147731173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Depriz.G!dha"
        threat_id = "2147731173"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Depriz"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 0c 17 ff c0 48 83 c2 02 66 83 e9 ?? 66 89 4a fe 83 f8 ?? 72 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "cmd.exe /c \"ping -n 30 127.0.0.1 >nul && sc config %s binpath= \"%s LocalService\" && ping -n 10 127.0.0.1 >nul && sc start %s" wide //weight: 1
        $x_1_3 = "The Maintenace Host service is hosted in the LSA process. The service provides key process isolation to private keys" wide //weight: 1
        $x_1_4 = "averfix2h826d_noaverir" wide //weight: 1
        $x_1_5 = "MaintenaceSrv64.exe" wide //weight: 1
        $x_1_6 = "MaintenaceSrv32.exe" wide //weight: 1
        $x_1_7 = "\\inf\\mdmnis5tQ1.pnf" wide //weight: 1
        $x_1_8 = "\\inf\\averbh_noav.pnf" wide //weight: 1
        $x_1_9 = "\\windows\\temp\\key8854321.pub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


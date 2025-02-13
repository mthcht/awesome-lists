rule Trojan_Win32_Ibashade_PA_2147751813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ibashade.PA!MTB"
        threat_id = "2147751813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ibashade"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rar$EX7.src777\\" ascii //weight: 1
        $x_1_2 = "%svmcis.exe" ascii //weight: 1
        $x_1_3 = "%svmcis.txt" ascii //weight: 1
        $x_1_4 = "pipe.Exc777.tmp" ascii //weight: 1
        $x_1_5 = "the shade doesn't want you death" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\winsvh" ascii //weight: 1
        $x_1_7 = "copy vrs to startup" ascii //weight: 1
        $x_1_8 = "ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f /t REG_SZ /v COMLOADER /d \"\\\\.\\%sProgram Files\\FoxitReader\\bin\\COM7.EXE\"" ascii //weight: 1
        $x_1_9 = "achsv.exe" ascii //weight: 1
        $x_1_10 = "dangerous.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


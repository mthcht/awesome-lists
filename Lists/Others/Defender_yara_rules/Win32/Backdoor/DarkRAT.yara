rule Backdoor_Win32_DarkRAT_AR_2147744028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkRAT.AR!MTB"
        threat_id = "2147744028"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe /C ping 127.0.0.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"" ascii //weight: 10
        $x_10_2 = "cmd.exe /k start" ascii //weight: 10
        $x_20_3 = "Set objWMIService = GetObject(\"winmgmts:\\\\\" & sComputerName & \"\\root\\cimv2\")" ascii //weight: 20
        $x_1_4 = "sQuery = \"SELECT * FROM Win32_Process\"" ascii //weight: 1
        $x_1_5 = "Set objShell = WScript.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_6 = "WScript.Sleep 1000" ascii //weight: 1
        $x_10_7 = "root\\SecurityCenter2" ascii //weight: 10
        $x_10_8 = "Select * From AntiVirusProduct" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}


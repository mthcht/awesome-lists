rule Worm_Win32_Savego_A_2147575181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Savego.A"
        threat_id = "2147575181"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Savego"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@ECHO OFF" ascii //weight: 1
        $x_1_2 = ":Repeat" ascii //weight: 1
        $x_1_3 = "DEL \"C:\\myapp.exe" ascii //weight: 1
        $x_1_4 = "Ping 0.0.0.0" ascii //weight: 1
        $x_1_5 = "IF EXIST \"C:\\myapp.exe\" GOTO Repeat" ascii //weight: 1
        $x_1_6 = "DEL \"%0\"" ascii //weight: 1
        $x_1_7 = "foo.com" ascii //weight: 1
        $x_1_8 = "%sNL%i%i%i.bat" ascii //weight: 1
        $x_1_9 = "net start \"Symantec AntiVirus\"" ascii //weight: 1
        $x_1_10 = "AgentIPPort" ascii //weight: 1
        $x_1_11 = "SOFTWARE\\Intel\\LANDesk\\VirusProtect6\\CurrentVersion" ascii //weight: 1
        $x_1_12 = "net stop SharedAccess" ascii //weight: 1
        $x_1_13 = "%s\\wins\\svchost.exe" ascii //weight: 1
        $x_1_14 = "net start \"Symantec AntiVirus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}


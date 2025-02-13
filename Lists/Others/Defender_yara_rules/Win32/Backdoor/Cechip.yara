rule Backdoor_Win32_Cechip_A_2147661716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cechip.A"
        threat_id = "2147661716"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cechip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "explorer.exe -ssh -R \"" ascii //weight: 1
        $x_1_2 = "\"+server+\" -l \"+username+\" -pw \"+password" ascii //weight: 1
        $x_1_3 = ".Environment(\"PROCESS\")" ascii //weight: 1
        $x_1_4 = "select * from win32_process where name='explorer.exe'" ascii //weight: 1
        $x_1_5 = "winlogon.exe -d -t -l -e0.0.0.0 -i127.0.0.1 -p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


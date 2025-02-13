rule Backdoor_Win32_GGDoor_A_2147576654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GGDoor.gen!A"
        threat_id = "2147576654"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GGDoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "800"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "zip c:\\plik.exe" ascii //weight: 100
        $x_100_2 = "zip c:\\plik.mp3 1.5" ascii //weight: 100
        $x_100_3 = "http://wojass.unitedcrew.net" ascii //weight: 100
        $x_100_4 = "http://unitedcrew.net" ascii //weight: 100
        $x_100_5 = "http://www.ggt.int.pl" ascii //weight: 100
        $x_100_6 = "directx22l.dll" ascii //weight: 100
        $x_100_7 = "telnet <IP> <port>" ascii //weight: 100
        $x_100_8 = "rootkit <opcja>" ascii //weight: 100
        $x_100_9 = "pass oe" ascii //weight: 100
        $x_100_10 = "pass ie" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}


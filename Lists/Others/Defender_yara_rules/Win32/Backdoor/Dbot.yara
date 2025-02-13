rule Backdoor_Win32_Dbot_A_2147597983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dbot.A"
        threat_id = "2147597983"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "auto.thestatistic.org/cmdp2.php?key=" ascii //weight: 1
        $x_1_2 = "sex.exe" ascii //weight: 1
        $x_1_3 = "expIorer.exe" ascii //weight: 1
        $x_1_4 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_5 = "InternetOpenA" ascii //weight: 1
        $x_1_6 = "Windows Firewall Service" ascii //weight: 1
        $x_1_7 = "Vrennae Knock" ascii //weight: 1
        $x_1_8 = "DBot Debug Window" ascii //weight: 1
        $x_1_9 = "Wintime.exe" ascii //weight: 1
        $x_1_10 = "Winfire.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


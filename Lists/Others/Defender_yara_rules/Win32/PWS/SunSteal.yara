rule PWS_Win32_SunSteal_A_2147596431_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/SunSteal.A"
        threat_id = "2147596431"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "SunSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetWindowThreadProcessId" ascii //weight: 1
        $x_1_2 = "CreateRemoteThread" ascii //weight: 1
        $x_1_3 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_4_5 = "Sungame.exe" ascii //weight: 4
        $x_3_6 = "/lin.asp" ascii //weight: 3
        $x_3_7 = "%s?rl=%d&s=%d&u=%s&p=%s&sp=%s&r=%s&l=%d&ml=%d&mh=%d" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


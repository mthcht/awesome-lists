rule Worm_Win32_Nedky_A_2147625273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nedky.A"
        threat_id = "2147625273"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://evilman.cn/m2.txt" ascii //weight: 1
        $x_1_2 = "kendy.txt" ascii //weight: 1
        $x_1_3 = "cmd /c del /f /a " ascii //weight: 1
        $x_1_4 = "[autorun]" ascii //weight: 1
        $x_1_5 = "shellexecute=Setup.pif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


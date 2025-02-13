rule Trojan_Win32_QQProtect_A_2147749685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQProtect.A!ibt"
        threat_id = "2147749685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQProtect"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url('res://kernel32.dll/picture.a5a')" ascii //weight: 1
        $x_1_2 = "onkeydown='if(window.event.keyCode==27)" ascii //weight: 1
        $x_1_3 = "*YiYuYanWoChiLe*.htm" ascii //weight: 1
        $x_1_4 = "C:\\TEMP\\Sysqemktmsv.exe" ascii //weight: 1
        $x_1_5 = "QQProtect.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Pierogi_BM_2147771303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pierogi.BM!MSR"
        threat_id = "2147771303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pierogi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUID.bin" ascii //weight: 1
        $x_1_2 = "https://escanor.live/rip/ace/" ascii //weight: 1
        $x_1_3 = "LoadDllFiles" ascii //weight: 1
        $x_1_4 = "terrell" ascii //weight: 1
        $x_1_5 = "lucretia" ascii //weight: 1
        $x_1_6 = "Send ScreenShot...." ascii //weight: 1
        $x_1_7 = "\\Application Data\\WMI-HOSTWINDOWS" ascii //weight: 1
        $x_1_8 = "http://www.google.com/bot.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


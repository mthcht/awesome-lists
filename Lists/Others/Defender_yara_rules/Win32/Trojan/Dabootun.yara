rule Trojan_Win32_Dabootun_A_2147686305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dabootun.A"
        threat_id = "2147686305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabootun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 65 20 66 61 6c 6c 73 20 76 69 73 69 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "Booting\\Shel\\svchost.exe" wide //weight: 1
        $x_1_3 = "Booting\\Shel\\Text.vbs" wide //weight: 1
        $x_1_4 = "Hi am Dasun Tharanga ...Thangalle" wide //weight: 1
        $x_1_5 = "Face book find me : (http://www.facebook.com/dasun.tharanga.142)." wide //weight: 1
        $x_1_6 = "taskkill.exe /f /t /im taskmgr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


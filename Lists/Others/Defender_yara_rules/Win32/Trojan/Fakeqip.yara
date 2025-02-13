rule Trojan_Win32_Fakeqip_2147616610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakeqip"
        threat_id = "2147616610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeqip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "Windows/system32/servic.exe" ascii //weight: 1
        $x_1_3 = "start Windows_Video" ascii //weight: 1
        $x_1_4 = "smtp.rambler.ru" ascii //weight: 1
        $x_1_5 = {00 70 61 73 73 77 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_6 = "Skins/service.exe" ascii //weight: 1
        $x_1_7 = "/install /silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


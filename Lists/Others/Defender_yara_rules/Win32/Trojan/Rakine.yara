rule Trojan_Win32_Rakine_A_2147597058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rakine.A"
        threat_id = "2147597058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rakine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "karine.co.kr/download/winupdate.sys" ascii //weight: 1
        $x_1_3 = "Update_Kil" ascii //weight: 1
        $x_1_4 = "takeit.exe" ascii //weight: 1
        $x_1_5 = "takeit.sys" ascii //weight: 1
        $x_1_6 = "220.95.231.197/install_count" ascii //weight: 1
        $x_1_7 = "winupdate.exe" ascii //weight: 1
        $x_1_8 = "220.95.231.197/access_count" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


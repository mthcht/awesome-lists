rule PWS_Win32_Pony_RU_2147730777_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Pony.RU"
        threat_id = "2147730777"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii //weight: 1
        $x_1_2 = "Software\\Martin Prikryl" ascii //weight: 1
        $x_1_3 = "Software\\FTPWare\\COREFTP\\Sites" ascii //weight: 1
        $x_1_4 = "Software\\VanDyke\\SecureFX" ascii //weight: 1
        $x_1_5 = "full address:s:" ascii //weight: 1
        $x_1_6 = "\\Jaxx\\Local Storage\\file__0.localstorage" ascii //weight: 1
        $x_1_7 = "superman" ascii //weight: 1
        $x_1_8 = "starwars" ascii //weight: 1
        $x_1_9 = "trustno1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Dtrack_B_2147904707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dtrack.B!dha"
        threat_id = "2147904707"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dtrack"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "/c ipconfig /all > \"%s\" & tasklist > \"%s\" & netstat -naop tcp > \"%s\"" ascii //weight: 100
        $x_100_2 = "/c ping -n 3 127.0.0.1 >NUL & echo EEEE > \"%s\"" ascii //weight: 100
        $x_100_3 = "%s\\netstat.res" ascii //weight: 100
        $x_100_4 = "%s\\task.list" ascii //weight: 100
        $x_100_5 = "%s\\res.ip" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Taskun_GP_2147853230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taskun.GP!MTB"
        threat_id = "2147853230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://valhalla.ipdns.hu:80/regchk.exe" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\regchk.exe" ascii //weight: 1
        $x_1_3 = "gateway@valhalla.ipdns.hu:/home/gateway/upload/" ascii //weight: 1
        $x_1_4 = "http://valhalla.ipdns.hu:80/put.php" ascii //weight: 1
        $x_1_5 = "C:\\Documents and Settings\\JohnDoe\\Application Data\\Adobeupdater.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


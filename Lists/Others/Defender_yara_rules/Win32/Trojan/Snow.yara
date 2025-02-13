rule Trojan_Win32_Snow_A_2147569695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snow.A"
        threat_id = "2147569695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Corporation. All rights reserved." wide //weight: 1
        $x_1_2 = "format Z:/x/q /Y" ascii //weight: 1
        $x_1_3 = "\\\\.\\Z:" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\SNOW" ascii //weight: 1
        $x_1_5 = "(ether dst FF:FF:FF:FF:FF:FF) && udp && (host 0.0.0.0)" ascii //weight: 1
        $x_1_6 = "D:\\del.txt" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "C:\\Program Files\\ActiveState Perl Dev Kit 6.0\\bin\\pdkdebug.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


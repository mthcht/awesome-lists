rule Trojan_Win32_Klabnel_A_2147717208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Klabnel.A"
        threat_id = "2147717208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Klabnel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0xdB45111cc9c3048EeFA525fDb9779aa06524B7A1.1376" ascii //weight: 1
        $x_1_2 = "virtual39499.net:9003" ascii //weight: 1
        $x_1_3 = "mine1.coinmine.pl:1999" ascii //weight: 1
        $x_1_4 = "cgminer 3.7.2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


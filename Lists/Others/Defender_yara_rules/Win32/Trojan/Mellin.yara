rule Trojan_Win32_Mellin_A_2147618508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mellin.A"
        threat_id = "2147618508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mellin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regedit.exe /s C:\\WINDOWS\\system\\sy.reg" wide //weight: 1
        $x_1_2 = "http://vbnet.mvps.org/resources/tools/getpublicip.shtml" wide //weight: 1
        $x_1_3 = "c:\\ip.txt" wide //weight: 1
        $x_1_4 = "Windows Mellinnium" wide //weight: 1
        $x_1_5 = {c7 45 b8 b0 3a 40 00 c7 45 b0 08 00 00 00 8d 55 b0 8d 4d c4 ff 15 10 11 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


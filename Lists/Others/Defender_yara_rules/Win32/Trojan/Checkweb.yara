rule Trojan_Win32_Checkweb_A_2147627919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Checkweb.A"
        threat_id = "2147627919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Checkweb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 55 53 45 52 00 50 41 53 53 00 4c 49 53 54 00 61 6e 6f 6e 79 6d 6f 75 73 00 58 3d 25 73 20 55 3d 25 73 20 4f 3d 25 73 20 48 3d 25 64 20 56 3d 25 64 20 45 3d}  //weight: 1, accuracy: High
        $x_1_2 = "{E6FB5E20-DE35-11CF-9C87-00AA005127ED}\\InProcServer32" ascii //weight: 1
        $x_1_3 = "https://www.icq.com/people/" ascii //weight: 1
        $x_1_4 = "WebMoney" ascii //weight: 1
        $x_1_5 = {33 fa 23 fb 33 fa 03 c6 03 c7 c1 c0 03 8b fb 8b 75 04 33 f9 23 f8 33 f9 03 d6 03 d7 c1 c2 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


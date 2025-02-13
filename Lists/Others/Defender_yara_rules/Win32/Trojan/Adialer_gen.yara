rule Trojan_Win32_Adialer_gen_A_2147575236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer_gen.A"
        threat_id = "2147575236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer_gen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 fa 40 75 07 83 65 f4 00 8b 55 f4 8b c2 c1 f8 04 c0 e1 02 0a c1 8b c8 8b 45 0c 88 08 8b cb c0 e3 06 0a 5d fc 83 c0 03 c1 f9 02 c0 e2 04 0a ca 88 58 ff 88 48 fe 89 45 0c 8a 07 84 c0 0f 85 34 ff ff ff}  //weight: 10, accuracy: High
        $x_10_2 = "rtaYDjwLg#fCS4E9nqVkhscOHbvm3RJ56xpTZI7lXi+WGo2Mu8KQB1dPUANze0Fy" ascii //weight: 10
        $x_1_3 = "Software\\Microsoft\\SystemCertificates\\TrustedPublisher\\Certificates" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing\\Trust Database\\0" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_7 = "Errore nel rilascio del certificato di attivazione." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adialer_gen_B_2147575237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adialer_gen.B"
        threat_id = "2147575237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer_gen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7b 61 64 75 6c 74 ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d 31 31 31 31 2d 31 31 31 31 31 31 31 31 31 31 31 31 7d}  //weight: 5, accuracy: Low
        $x_5_2 = "goicfboogidikkejccmclpieicihhlpo gjbkdo" ascii //weight: 5
        $x_2_3 = "\"%s\" PID:%d EXE:\"%s\"" ascii //weight: 2
        $x_2_4 = "ExeDeleteEvent" ascii //weight: 2
        $x_2_5 = "MyWinPop" ascii //weight: 2
        $x_2_6 = "_dmm_.exe" ascii //weight: 2
        $x_2_7 = "_foobar_.exe" ascii //weight: 2
        $x_1_8 = "http://www.google.com" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing\\Trust Database\\0" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3" ascii //weight: 1
        $x_1_11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ActiveX Cache" ascii //weight: 1
        $x_1_12 = "RegisterServiceProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}


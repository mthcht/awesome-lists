rule Trojan_Win32_Bepdro_A_2147622806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bepdro.A"
        threat_id = "2147622806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bepdro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 66 75 63 6b 00 00 00 ff ff ff ff 2d 00 00 00 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 00 00 ff ff ff ff 22 00 00 00 25 57 69 6e 44 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 42 65 65 70 2e 73 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bepdro_A_2147622806_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bepdro.A"
        threat_id = "2147622806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bepdro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "-fuck" ascii //weight: 1
        $x_1_4 = "safemon.dll" ascii //weight: 1
        $x_1_5 = "iebuddy.dll" ascii //weight: 1
        $x_1_6 = "RavMon.exe,avp.exe,360tray.exe,RSTray.exe" ascii //weight: 1
        $x_1_7 = "drivers\\Beep.sys" ascii //weight: 1
        $x_1_8 = "if exist" ascii //weight: 1
        $x_1_9 = "we04we05" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_SMSer_B_2147624267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SMSer.B"
        threat_id = "2147624267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SMSer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeginPaint" ascii //weight: 1
        $x_1_2 = "CreateDesktopW" ascii //weight: 1
        $x_1_3 = "RegSetValueExW" ascii //weight: 1
        $x_1_4 = {6a 73 33 ff 47 57 6a 65 53 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = "shutdown.exe -r -t 0 -f" ascii //weight: 1
        $x_1_6 = "http://%s.com/registerguid.php?guid={%s}&wid=%d&u=%d&number=%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SMSer_B_2147624267_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SMSer.B"
        threat_id = "2147624267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SMSer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s.com/registerguid.php?guid={%s}&wid=%d&u=%d&number=%d" wide //weight: 1
        $x_1_2 = "if exist %s goto loop" ascii //weight: 1
        $x_1_3 = "shutdown.exe -r -t 0 -f" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\WinLogon\\" wide //weight: 1
        $x_1_5 = "Userinit" wide //weight: 1
        $x_1_6 = "WinExec" ascii //weight: 1
        $x_1_7 = "HttpSendRequestW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SMSer_F_2147630880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SMSer.F"
        threat_id = "2147630880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SMSer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 54 00 45 00 58 00 50 00 4c 00 2e 00 45 00 58 00 45 00 00 00 12 00 00 00 41 00 4e 00 56 00 49 00 52 00 2e 00 45 00 58 00 45 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "O:\\delphi proj\\System Locker\\" wide //weight: 2
        $x_1_3 = {00 6e 61 64 73 67 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 6e 30 73 64 34 61 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 44 69 73 61 62 6c 65 53 61 66 65 4d 6f 64 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SMSer_G_2147632281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SMSer.G"
        threat_id = "2147632281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SMSer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Windows Security Alert" ascii //weight: 10
        $x_10_2 = {4f 00 3a 00 5c 00 64 00 65 00 6c 00 70 00 68 00 69 00 20 00 70 00 72 00 6f 00 6a 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 5c 00 [0-16] 5c 00 62 00 75 00 69 00 6c 00 64 00 [0-16] 5c 00 66 00 6f 00 72 00 6d 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_2_3 = "HKLM\\System\\CurrentControlSet\\Control\\SafeBoot" wide //weight: 2
        $x_1_4 = {52 00 45 00 47 00 20 00 41 00 44 00 44 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 20 00 2f 00 76 00 20 00 [0-8] 2e 00 65 00 78 00 65 00 20 00 2f 00 64 00}  //weight: 1, accuracy: Low
        $x_1_5 = "*VMWARE*" wide //weight: 1
        $x_1_6 = "*VBOX*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


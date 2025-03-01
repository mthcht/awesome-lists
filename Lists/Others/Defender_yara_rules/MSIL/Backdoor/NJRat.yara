rule Backdoor_MSIL_NJRat_A_2147717112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NJRat.A!bit"
        threat_id = "2147717112"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://pastebin.com/raw/" wide //weight: 1
        $x_1_2 = {57 65 62 43 6c 69 65 6e 74 00 52 65 70 6c 61 63 65}  //weight: 1, accuracy: High
        $x_1_3 = {41 73 73 65 6d 62 6c 79 00 4c 6f 61 64 00 4d 65 74 68 6f 64 49 6e 66 6f 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74}  //weight: 1, accuracy: High
        $x_1_4 = {20 c8 00 00 00 da b4 6f 2b 00 00 0a ?? 17 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NJRat_A_2147717112_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NJRat.A!bit"
        threat_id = "2147717112"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 76 00 [0-16] 52 00 65 00 73 00 74 00 61 00 72 00 74 00 76 00 [0-16] 43 00 6c 00 6f 00 73 00 65 00 76 00 [0-16] 4c 00 6f 00 61 00 64 00 50 00 6c 00 75 00 67 00 69 00 6e 00}  //weight: 2, accuracy: Low
        $x_2_2 = "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0" wide //weight: 2
        $x_2_3 = "[InternetShortcut]{0}URL={1}{0}" wide //weight: 2
        $x_1_4 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "schtasks /create /sc minute /mo" wide //weight: 1
        $x_1_6 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_7 = "SELECT * FROM FirewallProduct" wide //weight: 1
        $x_1_8 = "cmd.exe /k ping 0 & del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_NJRat_A_2147731388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NJRat.A!MTB"
        threat_id = "2147731388"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /F /IM PING.EXE" wide //weight: 1
        $x_1_2 = "shutdown -s -t 00" wide //weight: 1
        $x_1_3 = "alexgetman2018.ddns.net" wide //weight: 1
        $x_1_4 = "netsh firewall add allowedprogram" wide //weight: 1
        $x_1_5 = "netsh firewall delete allowedprogram" wide //weight: 1
        $x_1_6 = "cmd.exe /k ping 0 & del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


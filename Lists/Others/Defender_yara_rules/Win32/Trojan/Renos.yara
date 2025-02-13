rule Trojan_Win32_Renos_H_128079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Renos.H"
        threat_id = "128079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e [0-48] 2e 63 6f 6d 2f [0-32] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = "/S /AID=" ascii //weight: 10
        $x_10_3 = "http://alfaportal.com/c" ascii //weight: 10
        $x_10_4 = "CLSID\\{357A87ED-3E5D-437d-B334-DEB7EB4982A3}" ascii //weight: 10
        $x_10_5 = "program.exe" ascii //weight: 10
        $x_10_6 = "\\screen.html" ascii //weight: 10
        $x_10_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_8 = "AntivirusGold" ascii //weight: 10
        $x_10_9 = "Intel system tool" ascii //weight: 10
        $x_10_10 = "wininet" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Renos_BAD_134983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Renos.BAD"
        threat_id = "134983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 72 69 76 65 72 20 64 69 73 6b 2e 73 79 73 20 69 73 20 6f 75 74 20 6f 66 20 6d 65 6d 6f 72 79 00}  //weight: 2, accuracy: High
        $x_2_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 69 6e 66 65 63 74 65 64 21 20 49 74 20 69 73 20 72 65 63 6f 6d 6d 65 6e 64 65 64 20 74 6f 20 73 74 61 72 74 20 73 70 79 77 61 72 65 20 63 6c 65 61 6e 65 72 20 74 6f 6f 6c 2e 00}  //weight: 2, accuracy: High
        $x_2_3 = "Warning! Security report" ascii //weight: 2
        $x_2_4 = "Software\\Microsoft\\Security Center" ascii //weight: 2
        $x_1_5 = "Access violation at address" ascii //weight: 1
        $x_1_6 = {4e 6f 43 68 61 6e 67 69 6e 67 57 61 6c 6c 70 61 70 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}


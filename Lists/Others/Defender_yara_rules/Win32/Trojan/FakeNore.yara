rule Trojan_Win32_FakeNore_153257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeNore"
        threat_id = "153257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeNore"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scan in progress" wide //weight: 1
        $x_1_2 = "Scan complete" wide //weight: 1
        $x_1_3 = "http://pc-scan-online.com/l2.php?t=" wide //weight: 1
        $x_1_4 = "C:\\NetworkControl" wide //weight: 1
        $x_1_5 = "http://85.234.191." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeNore_153257_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeNore"
        threat_id = "153257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeNore"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_3_2 = "http://85.234.191.170/inst.php?id=" wide //weight: 3
        $x_2_3 = "C:\\NetworkControl\\nc.exe" wide //weight: 2
        $x_1_4 = "possible threats on your computer." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


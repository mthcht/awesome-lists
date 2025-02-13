rule Rogue_Win32_FakeKernav_172549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeKernav"
        threat_id = "172549"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeKernav"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Protection Center" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Quarantined" wide //weight: 1
        $x_1_4 = "Backdoor" wide //weight: 1
        $x_1_5 = "Flooder" wide //weight: 1
        $x_1_6 = "Trojan" wide //weight: 1
        $x_1_7 = "Sniffer" wide //weight: 1
        $x_1_8 = "SpamBot" wide //weight: 1
        $x_1_9 = "Rootkit" wide //weight: 1
        $x_1_10 = "Virus" wide //weight: 1
        $x_1_11 = "Kernel32.exe" wide //weight: 1
        $x_1_12 = "WKernel32.dll" wide //weight: 1
        $x_1_13 = "statistics.data" wide //weight: 1
        $x_1_14 = "uninstall.soft" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


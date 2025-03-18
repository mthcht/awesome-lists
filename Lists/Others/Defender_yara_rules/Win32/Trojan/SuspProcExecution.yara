rule Trojan_Win32_SuspProcExecution_A_2147924250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProcExecution.A"
        threat_id = "2147924250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProcExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 65 00 67 00 [0-8] 61 00 64 00 64 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\debugged_binary.exe" wide //weight: 1
        $x_1_3 = "MonitorProcess" wide //weight: 1
        $x_1_4 = "\\injected_binary.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProcExecution_B_2147924251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProcExecution.B"
        threat_id = "2147924251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProcExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 00 65 00 67 00 [0-8] 61 00 64 00 64 00 20 00}  //weight: 2, accuracy: Low
        $x_2_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\debugged_binary.exe" wide //weight: 2
        $x_2_3 = "MonitorProcess" wide //weight: 2
        $x_2_4 = "\\injected_binary.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


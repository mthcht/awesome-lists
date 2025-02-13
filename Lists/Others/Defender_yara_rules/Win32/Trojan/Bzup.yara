rule Trojan_Win32_Bzup_IV_2147597106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bzup.IV"
        threat_id = "2147597106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bzup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "agent_dq.dll" ascii //weight: 10
        $x_2_2 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 2
        $x_2_3 = "CreateToolhelp32Snapshot" ascii //weight: 2
        $x_2_4 = "OpenProcess" ascii //weight: 2
        $x_2_5 = "InternetOpenUrlA" ascii //weight: 2
        $x_2_6 = "ShellExecuteA" ascii //weight: 2
        $x_1_7 = "explorer.exe" ascii //weight: 1
        $x_1_8 = "FtpCreateDirectoryA" ascii //weight: 1
        $x_1_9 = "FtpFindFirstFileA" ascii //weight: 1
        $x_1_10 = "HttpSendRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


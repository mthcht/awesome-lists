rule TrojanSpy_Win32_Bzub_IX_2147603719_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bzub.IX"
        threat_id = "2147603719"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bzub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "agent_dq.dll" ascii //weight: 3
        $x_2_2 = "FtpOpenFileA" ascii //weight: 2
        $x_2_3 = "SHDeleteKeyA" ascii //weight: 2
        $x_2_4 = "ShellExecuteA" ascii //weight: 2
        $x_1_5 = "<description>My Office Addin built with .Net</description>" ascii //weight: 1
        $x_1_6 = "FtpCreateDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bzub_A_2147620158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bzub.A"
        threat_id = "2147620158"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bzub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "123ab%.8lx" ascii //weight: 10
        $x_10_2 = "IeHook.dll" ascii //weight: 10
        $x_10_3 = "\\hostwl.exe" ascii //weight: 10
        $x_10_4 = "\\flash.zip" ascii //weight: 10
        $x_10_5 = "payments.asp" ascii //weight: 10
        $x_1_6 = "http://www.microsoft.com" ascii //weight: 1
        $x_1_7 = "\\Macromedia\\Flash Player" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}


rule HackTool_Win32_Badcastle_A_2147775664_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Badcastle.A!dha"
        threat_id = "2147775664"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Badcastle"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\{0}\\pipe\\spoolss" wide //weight: 1
        $x_1_2 = "12345678-1234-ABCD-EF00-0123456789AB" wide //weight: 1
        $x_1_3 = "\\pipe\\samr" wide //weight: 1
        $x_1_4 = "LsarQueryInformationPolicy failed 0x" wide //weight: 1
        $x_1_5 = "[!] RpcRemoteFindFirstPrinterChangeNotificationEx fail!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


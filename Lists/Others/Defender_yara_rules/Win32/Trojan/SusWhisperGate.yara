rule Trojan_Win32_SusWhisperGate_MK_2147955532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWhisperGate.MK"
        threat_id = "2147955532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWhisperGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c for %G in (" ascii //weight: 1
        $x_1_2 = ".pdf, .doc, .wps, .docx, " ascii //weight: 1
        $x_1_3 = ".ppt, .xls, .xlsx, .pptx, .rtf) do " ascii //weight: 1
        $x_1_4 = "forfiles /p " ascii //weight: 1
        $x_1_5 = " /s /M *%G /C " ascii //weight: 1
        $x_1_6 = "cmd /c echo @PATH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


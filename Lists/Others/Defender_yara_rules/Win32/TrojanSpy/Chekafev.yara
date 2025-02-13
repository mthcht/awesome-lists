rule TrojanSpy_Win32_Chekafev_C_2147634566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Chekafev.C"
        threat_id = "2147634566"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Chekafev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskkill /f /im ZhuDongFangyu.exe" wide //weight: 2
        $x_2_2 = "cmd /c ping 127.0.0.1 -n 1 && del \"" wide //weight: 2
        $x_2_3 = "get.asp?mac=" wide //weight: 2
        $x_2_4 = "&makedate=" wide //weight: 2
        $x_2_5 = "&comput=" wide //weight: 2
        $x_2_6 = "&ver=" wide //weight: 2
        $x_2_7 = "&userid=" wide //weight: 2
        $x_1_8 = "wxsyncli.exe" wide //weight: 1
        $x_1_9 = "clsmn.exe" wide //weight: 1
        $x_1_10 = "rzxdwcltplug.exe" wide //weight: 1
        $x_1_11 = "nbclient.exe" wide //weight: 1
        $x_1_12 = "eway.exe" wide //weight: 1
        $x_1_13 = "barclient.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


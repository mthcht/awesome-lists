rule Worm_Win32_Syhotran_A_2147625060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Syhotran.A"
        threat_id = "2147625060"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Syhotran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Windows.Forms" ascii //weight: 1
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = "open=.\\SYS\\svchost.EXE -i" wide //weight: 1
        $x_1_4 = "shell\\1\\=Open" wide //weight: 1
        $x_1_5 = "shell\\2\\=Browser" wide //weight: 1
        $x_1_6 = "shell\\2\\Command=.\\SYS\\svchost.EXE -i" wide //weight: 1
        $x_1_7 = "shellexecute=.\\SYS\\svchost.EXE -i" wide //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


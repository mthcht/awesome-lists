rule Trojan_Win32_Axhuan_2147582338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Axhuan"
        threat_id = "2147582338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Axhuan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\xuhuan.ini" ascii //weight: 2
        $x_2_2 = "\\xuhuan.tmp" ascii //weight: 2
        $x_2_3 = "\\xuhuan.exe" ascii //weight: 2
        $x_2_4 = "[xuhuan]" ascii //weight: 2
        $x_2_5 = "\\SAM.dat" ascii //weight: 2
        $x_1_6 = "cmd.exe /C ipconfig -all>c:\\sys.tmp" ascii //weight: 1
        $x_1_7 = "c:\\sys.tmp" ascii //weight: 1
        $x_1_8 = "\\rmdrv.dll" ascii //weight: 1
        $x_1_9 = "\\rmdll.dll" ascii //weight: 1
        $x_1_10 = "MicroCSC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}


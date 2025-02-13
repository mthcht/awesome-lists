rule Backdoor_Win32_Zapchast_D_2147617814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zapchast.D"
        threat_id = "2147617814"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Greeting Card" ascii //weight: 1
        $x_10_2 = "firewall add allowedprogram C:\\WINDOWS\\Temp\\spool\\spoolsv.exe spoolsv" ascii //weight: 10
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\svchost\\Parameters" ascii //weight: 1
        $x_1_4 = "@$&%04\\taskbar.dll" ascii //weight: 1
        $x_10_5 = "@$&%04\\xmas.jpg" ascii //weight: 10
        $x_10_6 = "@$&%04\\dr.mrc" ascii //weight: 10
        $x_1_7 = "@$&%04\\popups.txt" ascii //weight: 1
        $x_10_8 = "+H +S @$&%02\\temp\\spool" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}


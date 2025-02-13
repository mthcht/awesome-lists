rule PWS_Win32_Dowque_A_2147582055_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dowque.A"
        threat_id = "2147582055"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dowque"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".com/ip/ip.php" ascii //weight: 2
        $x_2_2 = "Software\\Tencent\\Hook" ascii //weight: 2
        $x_1_3 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_4 = "Number=" ascii //weight: 1
        $x_2_5 = "&PassWord=" ascii //weight: 2
        $x_1_6 = "xxkxxxxjtr" ascii //weight: 1
        $x_1_7 = "yyyrt8jjj" ascii //weight: 1
        $x_1_8 = "SetWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


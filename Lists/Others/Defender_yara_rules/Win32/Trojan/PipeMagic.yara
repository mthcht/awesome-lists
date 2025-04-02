rule Trojan_Win32_PipeMagic_2147937661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PipeMagic!dha"
        threat_id = "2147937661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PipeMagic"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Parent PID: %u ..." ascii //weight: 1
        $x_1_2 = "SUCCESS ..." ascii //weight: 1
        $x_1_3 = "FAILED ..." ascii //weight: 1
        $x_1_4 = "IsMenu" ascii //weight: 1
        $x_1_5 = "Industry" ascii //weight: 1
        $x_1_6 = "%SYSTEMROOT%\\System32\\pcaui.exe" wide //weight: 1
        $x_1_7 = "%SYSTEMROOT%\\pcaui.exe" wide //weight: 1
        $x_1_8 = "%SYSTEMROOT%\\System32\\dvdplay.exe" wide //weight: 1
        $x_1_9 = "%SYSTEMROOT%\\dvdplay.exe" wide //weight: 1
        $x_1_10 = "%SYSTEMROOT%\\System32\\hh.exe" wide //weight: 1
        $x_1_11 = "%SYSTEMROOT%\\hh.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_PipeMagic_C_2147937662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PipeMagic.C!dha"
        threat_id = "2147937662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PipeMagic"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\pipe\\magic" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\1.%s" ascii //weight: 1
        $x_1_3 = ":fuckit" wide //weight: 1
        $x_1_4 = {6a 04 8d 4d f0 e8 [0-16] 6a 04 8d 4d f0 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c9 89 4d d8 89 4d dc 89 4d e0 66 c7 45 e4 00 01 89 4d f8 3c 5a 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


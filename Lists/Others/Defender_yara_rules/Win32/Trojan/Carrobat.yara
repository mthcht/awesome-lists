rule Trojan_Win32_Carrobat_C_2147730853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carrobat.C"
        threat_id = "2147730853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carrobat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c del /f /q" ascii //weight: 1
        $x_1_2 = "ren 1.txt 1.bat" ascii //weight: 1
        $x_1_3 = "&& 1.bat && exit" ascii //weight: 1
        $x_1_4 = "C: && cd %TEMP%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Carrobat_B_2147730854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carrobat.B"
        threat_id = "2147730854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carrobat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {63 65 72 74 75 74 69 6c 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70 3a 2f 2f [0-16] 2e 31 61 70 70 73 2e 63 6f 6d 2f 04 00 2e 74 78 74 20 25 74 65 6d 70 25 2f 04 00 2e 74 78 74 20 26 26 20 63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20 2d 66 20 25 74 65 6d 70 25 2f 25 74 65 6d 70 25 2f 04 00 2e 74 78 74 20 22 25 63 64 25}  //weight: 20, accuracy: Low
        $x_10_2 = "copy /Y %windir%\\System32\\certutil.exe %TEMP%\\ct.exe" ascii //weight: 10
        $x_10_3 = {63 74 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70 3a 2f 2f [0-16] 2e 31 61 70 70 73 2e 63 6f 6d 2f 04 00 2e 74 78 74 20 26 26 20 63 74 20 2d 64 65 63 6f 64 65 20 2d 66 20 04 00 2e 74 78 74 20 04 00 2e 62 61 74 20 26 26 20 64 65 6c 20 2f 66 20 2f 71 20 04 00 2e 74 78 74 20 26 26 20 04 00 2e 62 61 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}


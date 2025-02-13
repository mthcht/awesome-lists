rule Worm_Win32_Tophos_A_2147667378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tophos.A"
        threat_id = "2147667378"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tophos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.cadretest.ru/load.php" wide //weight: 1
        $x_1_2 = ":\\Photo.scr" wide //weight: 1
        $x_1_3 = "Undefended" wide //weight: 1
        $x_1_4 = {0f b7 54 45 ac 52 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 10 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 01 74 3d 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Tophos_C_2147681889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tophos.C"
        threat_id = "2147681889"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tophos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 80 4a 5d 05 e8 ?? ?? ?? ?? 05 00 e1 f5 05}  //weight: 1, accuracy: Low
        $x_4_2 = ":\\Photo\\Photo.exe" wide //weight: 4
        $x_4_3 = "/get.php?search=" wide //weight: 4
        $x_2_4 = ",porn," wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Tophos_E_2147695661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tophos.E"
        threat_id = "2147695661"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tophos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ru/exployer.exe" ascii //weight: 1
        $x_1_2 = "cmd /c chcp 1251 && systeminfo >" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


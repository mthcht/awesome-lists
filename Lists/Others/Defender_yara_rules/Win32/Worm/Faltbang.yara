rule Worm_Win32_Faltbang_A_2147625342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Faltbang.A"
        threat_id = "2147625342"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Faltbang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0b 68 40 7e 05 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 66 c7 45 cc 02 00 ff 15 ?? ?? ?? ?? 68 99 05 00 00 89 45 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {74 04 3c 2a 75 03 c6 01 5f 8d 85 ?? ?? ff ff 47 50 e8 ?? ?? ?? ?? 3b f8 59 72 b9}  //weight: 1, accuracy: Low
        $x_1_3 = "cmd /c lsnss.exe -S %s -U sa -P %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


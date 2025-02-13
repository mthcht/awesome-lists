rule Backdoor_Win32_Nosrawec_A_2147632080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nosrawec.A"
        threat_id = "2147632080"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nosrawec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 a1 0f 00 00 8d 85 ?? ?? ff ff 50 53 e8 ?? ?? ?? ?? 85 c0 0f 8e}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 09 00 00 00 e8 ?? ?? ?? ?? 40 69 c0 e8 03 00 00 50 b8 f4 01 00 00 e8 ?? ?? ?? ?? 5a 03 d0 89 55 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d f8 00 74 0d 8b 55 f8 a1 ?? ?? ?? ?? 8b 08 ff 51 38 8b 45 f8 e8 ?? ?? ?? ?? 8b c8 83 c1 04 8d 45 fc ba 01 00 00 00 e8 ?? ?? ?? ?? 83 7d fc 00 75 ac}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 53 0c 8b d8 85 db 74 3e 6a 00 68 41 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Nosrawec_B_2147646018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nosrawec.B"
        threat_id = "2147646018"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nosrawec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UseNagleS" ascii //weight: 1
        $x_1_2 = "TransmitFile" ascii //weight: 1
        $x_2_3 = "winupdate.bat" ascii //weight: 2
        $x_2_4 = {53 31 00 00 53 32 00 00 53 33 00 00 53 34 00 00 53 35 00 00 53 36 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Nosrawec_C_2147648897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nosrawec.C"
        threat_id = "2147648897"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nosrawec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&hl=tr&prmd=ilb&start=" ascii //weight: 2
        $x_2_2 = "http://www.google.com.tr/#q=" ascii //weight: 2
        $x_2_3 = "php?computername=" ascii //weight: 2
        $x_1_4 = ".exec" ascii //weight: 1
        $x_1_5 = ".gogl" ascii //weight: 1
        $x_1_6 = ".ddos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


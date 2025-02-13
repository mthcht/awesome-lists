rule TrojanDropper_Win32_Bifrose_ACI_2147606973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bifrose.ACI"
        threat_id = "2147606973"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d ec 83 c4 10 68 dc 17 40 00 51 e8 4d 01 00 00 8b d0 8d 4d e0 ff d6}  //weight: 5, accuracy: High
        $x_1_2 = "<f4shb4ng@#@puridee>" wide //weight: 1
        $x_1_3 = "RC4Passwort" wide //weight: 1
        $x_1_4 = "\\Decrypted.exe" wide //weight: 1
        $x_1_5 = ".exe" wide //weight: 1
        $x_1_6 = ".tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Bifrose_ACI_2147606973_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bifrose.ACI"
        threat_id = "2147606973"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {72 27 00 00 70 28 21 00 00 0a 72 31 00 00 70 28 19 00 00 0a 18 73 22 00 00 0a 0d 07 6f 23 00 00 0a d4 8d 11 00 00 01 13 04 07 11 04 16 11 04 8e 69 6f 24 00 00 0a 26 09 11 04 16 11 04 8e 69 6f 25 00 00 0a 08 6f 26 00 00 0a 09 6f 27 00 00 0a 2a}  //weight: 10, accuracy: High
        $x_10_2 = {28 05 00 00 06 72 27 00 00 70 28 21 00 00 0a 72 47 00 00 70 28 19 00 00 0a 07 28 2b 00 00 0a 73 2c 00 00 0a}  //weight: 10, accuracy: High
        $x_1_3 = "\\sysdx.exe" wide //weight: 1
        $x_1_4 = "\\vkd32.exe" wide //weight: 1
        $x_1_5 = "hideit.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Bifrose_F_2147643186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bifrose.F"
        threat_id = "2147643186"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Bifrost Stub Generator v" wide //weight: 4
        $x_2_2 = "C0nv3Rt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


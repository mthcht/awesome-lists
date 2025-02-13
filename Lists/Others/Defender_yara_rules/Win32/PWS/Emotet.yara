rule PWS_Win32_Emotet_E_2147690658_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Emotet.E"
        threat_id = "2147690658"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\mailpv.exe" ascii //weight: 1
        $x_1_2 = "\\mailpv.cfg" ascii //weight: 1
        $x_1_3 = "/sxml" ascii //weight: 1
        $x_1_4 = "/in/smtp.php" ascii //weight: 1
        $x_1_5 = {6a 00 6a 1a 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 00 6a 1a 68 ?? ?? ?? ?? 6a 00 ff d7}  //weight: 1, accuracy: Low
        $x_10_7 = {b8 1f 85 eb 51 f7 64 24 ?? c1 ea 05 83 fa 02 74 07 b8 02 00 00 00 eb 11 56 8b 35 ?? ?? ?? ?? ff d6 57 ff d6 53 ff d6 33 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Emotet_F_2147693399_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Emotet.F"
        threat_id = "2147693399"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\mailpv.exe" ascii //weight: 10
        $x_10_2 = "\\mailpv.cfg" ascii //weight: 10
        $x_10_3 = "/sxml" ascii //weight: 10
        $x_10_4 = "/in/smtp.php" ascii //weight: 10
        $x_1_5 = {6a 64 33 d2 59 f7 f1 83 f8 02 74 05 6a 02 58 eb 15 8b 35 ?? ?? ?? ?? 57 ff d6 ff 75 90 ff d6 ff 75 88 ff d6 33 c0}  //weight: 1, accuracy: Low
        $x_1_6 = {33 d2 6a 64 59 f7 f1 83 f8 02 74 05 6a 02 58 eb 11 56 8b 35 ?? ?? ?? ?? ff d6 53 ff d6 57 ff d6 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Emotet_G_2147695012_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Emotet.G"
        threat_id = "2147695012"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f 32 31 32 2e 37 31 2e 32 35 35 2e [0-3] 3a 34 34 33 2f [0-32] 2f 73 6d 74 70 2e 70 68 70}  //weight: 10, accuracy: Low
        $x_10_2 = {68 74 74 70 3a 2f 2f 39 34 2e 31 37 36 2e 32 2e [0-3] 3a 34 34 33 2f [0-32] 2f 73 6d 74 70 2e 70 68 70}  //weight: 10, accuracy: Low
        $x_1_3 = "/sxml" ascii //weight: 1
        $x_1_4 = "\"%s\" /c \"%s\"" ascii //weight: 1
        $x_1_5 = "\"%s\" %s \"%s\"" ascii //weight: 1
        $x_1_6 = "ComSpec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


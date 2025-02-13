rule PWS_Win32_Epizak_2147601602_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Epizak"
        threat_id = "2147601602"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Epizak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ivwt?)(" wide //weight: 1
        $x_5_2 = "User Name/Value" wide //weight: 5
        $x_1_3 = "/stext C:\\x.txt" wide //weight: 1
        $x_1_4 = "n.bat" wide //weight: 1
        $x_10_5 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 10, accuracy: Low
        $x_10_6 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


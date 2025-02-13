rule PWS_Win32_Iorgut_A_2147605036_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Iorgut.A"
        threat_id = "2147605036"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Iorgut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 (81|83) ea [0-4] e8 ?? ?? ?? ff 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ff 43 4e 75}  //weight: 10, accuracy: Low
        $x_10_2 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_3 = "frmprincipal" ascii //weight: 1
        $x_1_4 = "titulo=Iorgute" ascii //weight: 1
        $x_1_5 = "frysy.net" ascii //weight: 1
        $x_1_6 = "VerificandoResol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


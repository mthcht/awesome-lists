rule PWS_Win32_Nemqe_A_2147626418_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Nemqe.A"
        threat_id = "2147626418"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemqe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "UserSetting.ini" ascii //weight: 10
        $x_10_2 = "QqAccount.dll" ascii //weight: 10
        $x_10_3 = "TenQQAccount.dll" ascii //weight: 10
        $x_10_4 = {6a 64 ff d7 eb e4 68 ?? ?? 00 10 68 ?? ?? 00 10 68 e8 00 00 00 68 9f 05 07 00 e8 ?? ?? 00 00 68 ?? ?? 00 10 68 ?? ?? 00 10 68 e8 00 00 00 68 b7 2f 00 00 e8 ?? ?? 00 00}  //weight: 10, accuracy: Low
        $x_1_5 = "Hatanem.dat" ascii //weight: 1
        $x_1_6 = "suser=%s&spass=%s&serial=%s&serNum=%s&level=%d&money=%d&line=%s&flag=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Nemqe_B_2147628427_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Nemqe.B"
        threat_id = "2147628427"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemqe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 6e 6a 65 63 74 2e 64 6c 6c 00 4c 70 6b}  //weight: 1, accuracy: High
        $x_1_2 = {6a 2c 8b d8 53 e8 ?? ?? 00 00 83 c4 10 85 c0 75 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


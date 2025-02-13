rule Trojan_Win32_Dozlurk_A_2147690242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dozlurk.A"
        threat_id = "2147690242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozlurk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 6c 69 6e 6b 2e 75 63 6f 7a 2e 72 75 2f [0-3] 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_1_2 = "32\\svchost.exe" ascii //weight: 1
        $x_1_3 = "64\\svchost.exe" ascii //weight: 1
        $x_2_4 = "D:\\126\\Delphi\\HiAsm3\\compiler\\Kol.pas" ascii //weight: 2
        $x_1_5 = {46 6f 72 6d 00 00 00 00 41 53 4d 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


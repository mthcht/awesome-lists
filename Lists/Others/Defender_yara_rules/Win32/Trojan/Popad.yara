rule Trojan_Win32_Popad_2147616265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Popad"
        threat_id = "2147616265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Popad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SmplWndPopup" ascii //weight: 10
        $x_10_2 = {70 00 6f 00 70 00 75 00 6e 00 64 00 65 00 72 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = "F7759ABC-B7D8-437C-ADC4-B35F2E1692CC" wide //weight: 10
        $x_2_4 = "info.pops-icle.com" ascii //weight: 2
        $x_2_5 = "PopsicleModule" ascii //weight: 2
        $x_2_6 = {50 6f 70 73 69 63 6c 65 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 2, accuracy: High
        $x_2_7 = "pops-icle.com/ad.html" wide //weight: 2
        $x_2_8 = "Software\\LowRegistry\\Popsicle" wide //weight: 2
        $x_1_9 = {41 00 44 00 56 00 50 00 72 00 6f 00 5f 00 [0-5] 70 00 6f 00 70 00 75 00 70 00}  //weight: 1, accuracy: Low
        $x_1_10 = "LastADTC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}


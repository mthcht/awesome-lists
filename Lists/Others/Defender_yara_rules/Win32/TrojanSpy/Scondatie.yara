rule TrojanSpy_Win32_Scondatie_A_2147656125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Scondatie.A"
        threat_id = "2147656125"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Scondatie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "l.asp?id=%s&dd=%0:s&os=%s&mac=GG&v=%s" wide //weight: 1
        $x_1_2 = "sina_keyword_ad_area2" wide //weight: 1
        $x_1_3 = "(\"action\", \"BuycardChoseCard\");$(\"#choseCard\").submit();" wide //weight: 1
        $x_1_4 = "z.asp?id=%s&and=%0:s&bank=%s&money=%s&fanhui=0" wide //weight: 1
        $x_1_5 = {56 00 61 00 6c 00 69 00 64 00 61 00 74 00 65 00 43 00 6f 00 64 00 65 00 2e 00 61 00 73 00 68 00 78 00 3f 00 74 00 3d 00 22 00 2b 00 74 00 69 00 6d 00 65 00 6e 00 6f 00 77 00 3b 00 7d 00 [0-16] 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 73 00 62 00 66 00 6d 00 2e 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 22 00 41 00 6c 00 69 00 70 00 61 00 79 00 43 00 6f 00 64 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


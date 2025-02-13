rule BrowserModifier_Win32_Maibeeser_241045_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Maibeeser"
        threat_id = "241045"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Maibeeser"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\mbs_install" wide //weight: 1
        $x_1_2 = "Software\\mybeesearch" wide //weight: 1
        $x_1_3 = "accept_cert.Properties.Resources" wide //weight: 1
        $x_1_4 = "/writeregkey" wide //weight: 1
        $x_1_5 = {50 00 72 00 6f 00 78 00 79 00 53 00 65 00 72 00 76 00 65 00 72 00 [0-4] 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 3a 00 38 00 30 00 30 00 33 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 52 65 6c 65 61 73 65 5c 72 75 6e 6e 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_7 = "olk alkdjf dsaa d oakjlsfd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Maibeeser_241045_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Maibeeser"
        threat_id = "241045"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Maibeeser"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\mbs_install" wide //weight: 1
        $x_1_2 = "www.mybeesearch.com" wide //weight: 1
        $x_1_3 = "www.beleelashoppersearch.com" wide //weight: 1
        $x_1_4 = "www.betteradssoftware.com" wide //weight: 1
        $x_1_5 = "Software\\betterads" wide //weight: 1
        $x_1_6 = "www.updaterserver.com/srcsrvupdt/update_check.php" wide //weight: 1
        $x_1_7 = "winsrcsrv.exe" wide //weight: 1
        $x_1_8 = "coinis9" wide //weight: 1
        $x_1_9 = "src_srv_api/report_install.php" wide //weight: 1
        $x_1_10 = "betterads-ads.net/fetch.php?p=1" wide //weight: 1
        $x_2_11 = "\\betterads\\rootCert.pfx" wide //weight: 2
        $x_2_12 = {5c 52 65 6c 65 61 73 65 5c 77 69 6e 73 72 63 73 72 76 2e 70 64 62 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


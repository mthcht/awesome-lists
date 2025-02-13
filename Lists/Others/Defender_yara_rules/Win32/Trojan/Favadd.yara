rule Trojan_Win32_Favadd_T_2147603254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Favadd.T"
        threat_id = "2147603254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Favadd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 3a 5c 00 55 52 4c 00 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 00 00 00 00 30 00 00 00 49 63 6f 6e 49 6e 64 65 78 00 00 00 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 00 00 00 00 49 63 6f 6e 46 69 6c 65 00 00 00 00 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 00 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 10, accuracy: High
        $x_1_2 = "Online Pharmacy.url" ascii //weight: 1
        $x_1_3 = "Sexual Enhancers.url" ascii //weight: 1
        $x_1_4 = "Swinger Clubs.url" ascii //weight: 1
        $x_1_5 = "Online Casino.url" ascii //weight: 1
        $x_1_6 = "Black Jack.url" ascii //weight: 1
        $x_1_7 = "Online Poker.url" ascii //weight: 1
        $x_1_8 = "Online Dating.url" ascii //weight: 1
        $x_1_9 = "Remove Spyware.url" ascii //weight: 1
        $x_1_10 = "Network Security.url" ascii //weight: 1
        $x_1_11 = "Spam Filters.url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Favadd_C_2147636783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Favadd.C"
        threat_id = "2147636783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Favadd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\" /e /c /r \"Authenticated Users\"" wide //weight: 1
        $x_2_2 = "360SE.exe|avant.exe|AcooBrowser.exe|AdoIE.EXE|AH" wide //weight: 2
        $x_3_3 = "\\Intrenet  Explorer.lnk" wide //weight: 3
        $x_2_4 = "http://taobao.lo" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


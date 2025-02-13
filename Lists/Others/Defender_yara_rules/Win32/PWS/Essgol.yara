rule PWS_Win32_Essgol_A_2147574092_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Essgol.gen!A"
        threat_id = "2147574092"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Essgol"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AccountID=%s&PassPhrase=%s&Amount=%s&Email=%s" ascii //weight: 4
        $x_2_2 = "closeeventegold1" ascii //weight: 2
        $x_2_3 = "CLSID\\{92617934" ascii //weight: 2
        $x_1_4 = "AccountID=" ascii //weight: 1
        $x_1_5 = "PassPhrase=" ascii //weight: 1
        $x_1_6 = "https://www.e-gold.com/" ascii //weight: 1
        $x_1_7 = "acct/acct.asp" ascii //weight: 1
        $x_1_8 = "acct/accountinfo.asp" ascii //weight: 1
        $x_1_9 = "acct/balance.asp" ascii //weight: 1
        $x_1_10 = "User-Agent:" ascii //weight: 1
        $x_1_11 = "Accept-Encoding:" ascii //weight: 1
        $x_1_12 = "=Disabled" ascii //weight: 1
        $x_1_13 = "SecurityLevel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


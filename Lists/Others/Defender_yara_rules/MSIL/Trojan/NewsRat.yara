rule Trojan_MSIL_NewsRat_MA_2147888455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NewsRat.MA!MTB"
        threat_id = "2147888455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NewsRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 02 8e 69 6f ?? ?? ?? 06 8d 18 00 00 01 0d 07 02 16 02 8e 69 09 16 6f ?? ?? ?? 06 13 04 07 09 11 04}  //weight: 5, accuracy: Low
        $x_2_2 = "C:\\ProgramData\\Data\\cookies_fb.txt" wide //weight: 2
        $x_2_3 = "C:\\ProgramData\\Data\\all_account.txt" wide //weight: 2
        $x_2_4 = "\\Network\\Cookies" wide //weight: 2
        $x_2_5 = "\\Local\\CocCoc\\Browser\\User Data" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


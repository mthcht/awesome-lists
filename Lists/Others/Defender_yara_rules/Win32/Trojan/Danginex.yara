rule Trojan_Win32_Danginex_2147636053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danginex"
        threat_id = "2147636053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danginex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/xml_lost_ad.asp?ad_url=" ascii //weight: 1
        $x_1_2 = "niudoudou.com/web/getinfo.asp?ver=%d" ascii //weight: 1
        $x_1_3 = "niudoudou.com/web/updateuser.asp?id=" ascii //weight: 1
        $x_1_4 = "TRSOCR_ini.dll" ascii //weight: 1
        $x_1_5 = "TRSOCR_data.dll" ascii //weight: 1
        $x_1_6 = "AdvOcr.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


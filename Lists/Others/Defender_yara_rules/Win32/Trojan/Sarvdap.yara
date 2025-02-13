rule Trojan_Win32_Sarvdap_A_2147682554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sarvdap.A"
        threat_id = "2147682554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarvdap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "sid=%s:ver=%s:login=%s:pass=%s:port=%u" ascii //weight: 100
        $x_15_2 = "MS_UNAT_MODULE_TO_START" ascii //weight: 15
        $x_10_3 = "save-pandas.net" ascii //weight: 10
        $x_10_4 = "peace-with-abama.org" ascii //weight: 10
        $x_10_5 = "ilovemicrosoftverymach.com" ascii //weight: 10
        $x_10_6 = "palletsalbum.org" ascii //weight: 10
        $x_10_7 = "rbl.txt?sign=%s&numba=%u" ascii //weight: 10
        $x_5_8 = {62 6c 2e 73 70 61 6d 63 61 6e 6e 69 62 61 6c 2e 6f 72 67 0a 62 6c 2e 73 70 61 6d 63 6f 70 2e 6e 65 74 0a 70 62 6c 2e 73 70 61 6d 68 61 75 73 2e 6f 72 67}  //weight: 5, accuracy: High
        $x_5_9 = "srv_666" ascii //weight: 5
        $x_5_10 = "74hhdsfbweyuYGHuiebwedwedwINDWNBDW" ascii //weight: 5
        $x_5_11 = "Yjdne783nbGGwt73h" ascii //weight: 5
        $x_5_12 = ".org:2389/ip.php" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 4 of ($x_5_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 4 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 5 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}


rule Worm_Win32_Korgo_2147555610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Korgo"
        threat_id = "2147555610"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Korgo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avserve.exe" ascii //weight: 1
        $x_1_2 = "ftpupd.exe" ascii //weight: 1
        $x_1_3 = "Bot Loader" ascii //weight: 1
        $x_2_4 = "avserve2.exeUpdate Service" ascii //weight: 2
        $x_1_5 = "http://%s:%d/x.exe" ascii //weight: 1
        $x_2_6 = "Xhttp://127.0.0.1:800/e.exe" ascii //weight: 2
        $x_3_7 = "C:\\WINDOWS\\SYSTEM\\kzalap.exe" ascii //weight: 3
        $x_2_8 = "MS Config v13" ascii //weight: 2
        $x_1_9 = "adult-empire.com" ascii //weight: 1
        $x_1_10 = "citi-bank.ru" ascii //weight: 1
        $x_1_11 = "color-bank.ru" ascii //weight: 1
        $x_1_12 = "crutop.nu" ascii //weight: 1
        $x_1_13 = "filesearch.ru" ascii //weight: 1
        $x_1_14 = "kidos-bank.ru" ascii //weight: 1
        $x_1_15 = "konfiskat.org" ascii //weight: 1
        $x_1_16 = "master-x.com" ascii //weight: 1
        $x_1_17 = "parex-bank.ru" ascii //weight: 1
        $x_1_18 = "www.redline.ru" ascii //weight: 1
        $x_1_19 = "xware.cjb.net" ascii //weight: 1
        $x_1_20 = "asechka.ru" ascii //weight: 1
        $x_1_21 = "mazafaka.ru" ascii //weight: 1
        $x_1_22 = "fethard.biz" ascii //weight: 1
        $x_1_23 = "kavkaz.tv" ascii //weight: 1
        $x_1_24 = "roboxchange.com" ascii //weight: 1
        $x_1_25 = ")B1kzalap.exe" ascii //weight: 1
        $x_1_26 = "0AB1cvv.ru" ascii //weight: 1
        $x_1_27 = "http://%s/index.php?id=%s&scn=%d&inf=%d&ver=19&cnt=%s" ascii //weight: 1
        $x_1_28 = "http://%s/index.php?id=%s&scn=%d&inf=%d&ver=19-2&cnt=%s" ascii //weight: 1
        $x_3_29 = "C:\\WINDOWS\\SYSTEM\\odspea.exe" ascii //weight: 3
        $x_1_30 = "http://%s/index.php?id=%s&scn=%d&inf=%d&ver=20&cnt=%s" ascii //weight: 1
        $x_1_31 = "http://%s/index.php?id=%s&scn=%d&inf=%d&ver=19.2&cnt=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Korgo_B_2147649380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Korgo.gen!B"
        threat_id = "2147649380"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Korgo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://127.0.0.1:800/" ascii //weight: 1
        $x_1_2 = {61 76 73 65 72 76 65 32 2e 65 78 65 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 74 65 72 6d 31 33 2e 32 69 00}  //weight: 1, accuracy: High
        $x_1_4 = "Bot Loader" ascii //weight: 1
        $x_2_5 = {ff d6 8d 45 e8 33 ff 50 57 6a 01 ff 75 08 57 57 53 ff 55 ec 3b c7 74 ?? 50 ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


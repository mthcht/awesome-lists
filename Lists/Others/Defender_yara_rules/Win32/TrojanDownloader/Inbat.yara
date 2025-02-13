rule TrojanDownloader_Win32_Inbat_A_2147642541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inbat.A"
        threat_id = "2147642541"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inbat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%MYFILES%\\Upd.exe" ascii //weight: 3
        $x_3_2 = "%MYFILES%\\in.exe" ascii //weight: 3
        $x_3_3 = "//www.xunlei100.com/msn/" ascii //weight: 3
        $x_3_4 = "//install.xinruicn.com" ascii //weight: 3
        $x_3_5 = "//to2.5cnd.com/" ascii //weight: 3
        $x_3_6 = "//a.xwxiazai.com/" ascii //weight: 3
        $x_1_7 = "/bibibei" ascii //weight: 1
        $x_1_8 = "/coopen_setup_" ascii //weight: 1
        $x_1_9 = "pipi\\unins000.exe\" /f" ascii //weight: 1
        $x_1_10 = "/DDHYT.exe" ascii //weight: 1
        $x_1_11 = "/pipi_dae_" ascii //weight: 1
        $x_1_12 = "/kugou_" ascii //weight: 1
        $x_1_13 = "/36a11.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Inbat_C_2147643453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inbat.C"
        threat_id = "2147643453"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inbat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%MYFILES%\\Upd.exe" ascii //weight: 2
        $x_2_2 = "http://%computername%" ascii //weight: 2
        $x_1_3 = ".fengyou.net/" ascii //weight: 1
        $x_1_4 = ".naige.com.cn/" ascii //weight: 1
        $x_1_5 = "http://www.xunlei100.com" ascii //weight: 1
        $x_1_6 = {00 55 50 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "pipi_dae_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Inbat_G_2147643699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inbat.G"
        threat_id = "2147643699"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inbat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%MYFILES%\\in.exe" ascii //weight: 2
        $x_1_2 = "http://stat.02933.com" ascii //weight: 1
        $x_1_3 = "mshta vbscript:createobject(\"wscript.shell\").run(\"\"\"iexplore\"\"http://" ascii //weight: 1
        $x_1_4 = "\\360safe.exe" ascii //weight: 1
        $x_1_5 = "\\KSWebShield.exe" ascii //weight: 1
        $x_1_6 = "\\kws.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Inbat_H_2147644531_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inbat.H"
        threat_id = "2147644531"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inbat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cnzz.sjt8.com/info.access/?stat_%var%" ascii //weight: 1
        $x_1_2 = "del %MYFILES% /f /s /q" ascii //weight: 1
        $x_1_3 = {64 65 6c 20 22 25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 5c a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c c6 f4 b6 af 5c 2a 2e 2a 22}  //weight: 1, accuracy: High
        $x_1_4 = {64 65 6c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c [0-6] 5c 75 6e 69 6e 73 30 30 30 2e 65 78 65 22 20 2f 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


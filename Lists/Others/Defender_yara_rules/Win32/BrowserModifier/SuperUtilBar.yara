rule BrowserModifier_Win32_SuperUtilBar_17578_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SuperUtilBar"
        threat_id = "17578"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SuperUtilBar"
        severity = "12"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://www.6781.com/city/" ascii //weight: 5
        $x_5_2 = "http://www.6781.com/navhtm/nav" ascii //weight: 5
        $x_4_3 = "http://www.shiyongsousuo.com" ascii //weight: 4
        $x_5_4 = "03D0C547-EBAD-43d9-8B57-DE16E7A93B52" ascii //weight: 5
        $x_5_5 = "6781ToolBar.dll" ascii //weight: 5
        $x_5_6 = "superutilbar.dll" ascii //weight: 5
        $x_1_7 = " http://www.imobile.com.cn/" ascii //weight: 1
        $x_1_8 = " http://www.stockstar.com/" ascii //weight: 1
        $x_1_9 = " http://www.flashempire.com/" ascii //weight: 1
        $x_1_10 = " http://www.dianping.com/" ascii //weight: 1
        $x_1_11 = " http://www.pclady.com.cn/" ascii //weight: 1
        $x_1_12 = " http://www.96333.com/" ascii //weight: 1
        $x_1_13 = " http://www.bokee.com/" ascii //weight: 1
        $x_1_14 = " http://www.qihoo.com/" ascii //weight: 1
        $x_1_15 = " http://www.sportscn.com/" ascii //weight: 1
        $x_1_16 = " http://www.tiexue.net/" ascii //weight: 1
        $x_1_17 = " http://www.cmbchina.com/" ascii //weight: 1
        $x_1_18 = " http://www.icbc.com.cn/" ascii //weight: 1
        $x_1_19 = " http://www.joyo.com/" ascii //weight: 1
        $x_1_20 = " http://www.dangdang.com/" ascii //weight: 1
        $x_1_21 = " http://www.onlinedown.net/" ascii //weight: 1
        $x_1_22 = "YouTube http://www.youtube.com/" ascii //weight: 1
        $x_1_23 = " http://www.bliao.com/" ascii //weight: 1
        $x_1_24 = "17173" ascii //weight: 1
        $x_1_25 = " http://www.17173.com/" ascii //weight: 1
        $x_1_26 = " http://www.cmfu.com/" ascii //weight: 1
        $x_1_27 = "MP3 http://mp3.baidu.com/" ascii //weight: 1
        $x_5_28 = "http://www.6781.com/tools/#" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 21 of ($x_1_*))) or
            ((2 of ($x_5_*) and 20 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 16 of ($x_1_*))) or
            ((3 of ($x_5_*) and 15 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((4 of ($x_5_*) and 10 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((6 of ($x_5_*))) or
            (all of ($x*))
        )
}


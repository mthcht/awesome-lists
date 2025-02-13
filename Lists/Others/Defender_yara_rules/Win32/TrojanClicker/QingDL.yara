rule TrojanClicker_Win32_QingDL_17732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/QingDL"
        threat_id = "17732"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "QingDL"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\cpr.ini" ascii //weight: 1
        $x_4_2 = "%s\\kwbuf.ini" ascii //weight: 4
        $x_4_3 = "%s\\toolset.ini" ascii //weight: 4
        $x_5_4 = "{841B2B65-118D-4FF2-AD63-4CFF44B8B68F}" wide //weight: 5
        $x_5_5 = "{DFCB34B6-902D-426E-AE2B-1B294AE19F4F}" ascii //weight: 5
        $x_10_6 = "BaiduXmlMapping wildfire %d" ascii //weight: 10
        $x_5_7 = "cns.3721.com/cns.dl" ascii //weight: 5
        $x_5_8 = "Edition=1&BarName=baidu&Name=" ascii //weight: 5
        $x_1_9 = "show_weather(\"" ascii //weight: 1
        $x_1_10 = "http://club.book.sina.com.cn/booksearch/booksearch.php?kw=%s" ascii //weight: 1
        $x_1_11 = "http://d.sogou.com/music.so?query=%s" ascii //weight: 1
        $x_1_12 = "http://download.enet.com.cn/search.php?keyword=%s" ascii //weight: 1
        $x_1_13 = "http://find.verycd.com/folders?cat=movie&kw=%s" ascii //weight: 1
        $x_1_14 = "http://foo.w97.cn/data/file/kwbuf.ini" ascii //weight: 1
        $x_1_15 = "http://foo.w97.cn/SoftInterFace/SearchNum.aspx" ascii //weight: 1
        $x_1_16 = "http://games.enet.com.cn/article/SearchCategory.php?key=%s" ascii //weight: 1
        $x_1_17 = "http://html.hjsm.tom.com/?mod=book&act=anonsearch&key=%s" ascii //weight: 1
        $x_1_18 = "http://image.soso.com/image.cgi?w=%s" ascii //weight: 1
        $x_1_19 = "http://images.google.cn/images?q=%s" ascii //weight: 1
        $x_1_20 = "http://img.zhongsou.com/i?w=%s" ascii //weight: 1
        $x_1_21 = "http://ks.pcgames.com.cn/games_index.jsp?q=%s" ascii //weight: 1
        $x_1_22 = "http://ks.pconline.com.cn/index.jsp?qx=download&q=%s" ascii //weight: 1
        $x_1_23 = "http://mp3.baidu.com/m?tn=baidump3lyric&ct=" ascii //weight: 1
        $x_1_24 = "http://mp3.baidu.com/m?tn=" ascii //weight: 1
        $x_1_25 = "http://mp3.zhongsou.com/m?w=%s" ascii //weight: 1
        $x_1_26 = "http://music.cn.yahoo.com/lyric.html?p=%s" ascii //weight: 1
        $x_1_27 = "http://music.soso.com/q?sc=mus&w=%s" ascii //weight: 1
        $x_1_28 = "http://p.iask.com/p?k=%s" ascii //weight: 1
        $x_1_29 = "http://p.zhongsou.com/p?w=%s" ascii //weight: 1
        $x_1_30 = "http://pic.sogou.com/pics?query=%s" ascii //weight: 1
        $x_1_31 = "http://search.17173.com/index.jsp?keyword=%s" ascii //weight: 1
        $x_1_32 = "http://search.btchina.net/search.php?query=%s" ascii //weight: 1
        $x_1_33 = "http://search.crsky.com/search.asp?sType=ResName&keyword=%s" ascii //weight: 1
        $x_1_34 = "http://search.dangdang.com/dangdang.dll?mode=1020&catalog=100&key1=%s" ascii //weight: 1
        $x_1_35 = "http://search.games.sina.com.cn/cgi-bin/game_search/game_deal.cgi?keywords=%s" ascii //weight: 1
        $x_1_36 = "http://search.newhua.com/search.asp?Keyword=%s" ascii //weight: 1
        $x_1_37 = "http://search.union.yahoo.com.cn/click/search.htm?m=" ascii //weight: 1
        $x_1_38 = "http://v.baidu.com/srh.php?tn=oliver1_dg&word=%s" ascii //weight: 1
        $x_1_39 = "http://v.iask.com/v?tag=&k=%s" ascii //weight: 1
        $x_1_40 = "http://weather.265.com/%s" ascii //weight: 1
        $x_1_41 = "http://weather.265.com/get_weather.php?action=get_city" ascii //weight: 1
        $x_1_42 = "http://www.baidu.com/baidu?tn=" ascii //weight: 1
        $x_1_43 = "http://www.daybt.com/query.asp?q=%s" ascii //weight: 1
        $x_1_44 = "http://www.google.cn/search?q=%s" ascii //weight: 1
        $x_1_45 = "http://www.iask.com/s?k=%s" ascii //weight: 1
        $x_1_46 = "http://www.iciba.com/search?s=%s" ascii //weight: 1
        $x_1_47 = "http://www.ip.com.cn/idcard.php?q=%s" ascii //weight: 1
        $x_1_48 = "http://www.ip.com.cn/ip.php?q=%s" ascii //weight: 1
        $x_1_49 = "http://www.ip.com.cn/mobile.php?q=%s" ascii //weight: 1
        $x_1_50 = "http://www.ip.com.cn/tel.php?q=%s" ascii //weight: 1
        $x_1_51 = "http://www.sogou.com/web?query=%s" ascii //weight: 1
        $x_1_52 = "http://www.soso.com/q?w=%s" ascii //weight: 1
        $x_1_53 = "http://www.tq121.com.cn/" ascii //weight: 1
        $x_1_54 = "http://www.wosss.com/search.aspx?q=%s" ascii //weight: 1
        $x_1_55 = "http://www.yodao.com/search?ue=utf8&q=%s" ascii //weight: 1
        $x_1_56 = "http://yc.book.sohu.com/series_list.php?select=1&text=%s" ascii //weight: 1
        $x_1_57 = "http://ys.cn.yahoo.com/mohu/index.html?p=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 47 of ($x_1_*))) or
            ((4 of ($x_5_*) and 50 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 46 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_4_*) and 42 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 47 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 50 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 46 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 42 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 45 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 41 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_4_*) and 37 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 40 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_4_*) and 36 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_4_*) and 32 of ($x_1_*))) or
            (all of ($x*))
        )
}


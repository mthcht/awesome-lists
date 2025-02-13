rule SoftwareBundler_Win32_WinOptimizer_206677_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/WinOptimizer"
        threat_id = "206677"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "WinOptimizer"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 64 00 73 00 5f 00 70 00 6f 00 73 00 74 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 00 64 00 73 00 5f 00 65 00 78 00 65 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 77 00 69 00 6e 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "WindowsOptimizer" wide //weight: 1
        $x_1_4 = "\\adsinfo.log" wide //weight: 1
        $x_1_5 = "avasts-mon" wide //weight: 1
        $x_1_6 = "app.topvideosoft.com/api_ajax.ashx?action=downloadlist&clientid" wide //weight: 1
        $x_1_7 = {3c 00 62 00 72 00 2f 00 3e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 00 64 00 73 00 5f 00 69 00 64 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 00 64 00 73 00 5f 00 75 00 72 00 6c 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 77 69 6e 68 65 6c 70 65 72 ?? ?? ?? 56 63 6c 2e 46 69 6c 65 43 74 72 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule SoftwareBundler_Win32_WinOptimizer_206677_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/WinOptimizer"
        threat_id = "206677"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "WinOptimizer"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Optimizer\\" wide //weight: 1
        $x_1_2 = "last_ads_" wide //weight: 1
        $x_1_3 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 6f 00 66 00 66 00 69 00 63 00 65 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Windows is updating(%s)..." wide //weight: 1
        $x_1_6 = "YouTubeDownload" wide //weight: 1
        $x_1_7 = "app.topvideosoft.com/adspostback_server.aspx?userid=" wide //weight: 1
        $x_1_8 = "app.download-server.org/ws/reportws.asmx?wsdl" wide //weight: 1
        $x_1_9 = {75 00 6e 00 6b 00 6e 00 6f 00 77 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_10 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule SoftwareBundler_Win32_WinOptimizer_206677_2
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/WinOptimizer"
        threat_id = "206677"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "WinOptimizer"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Optimizer\\" wide //weight: 1
        $x_1_2 = "last_ads_" wide //weight: 1
        $x_1_3 = "YouTubeDownload" wide //weight: 1
        $x_1_4 = "\\adsimage\\" wide //weight: 1
        $x_1_5 = {61 00 70 00 70 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2d 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2f 00 77 00 73 00 2f 00 [0-16] 2e 00 61 00 73 00 6d 00 78 00 3f 00 77 00 73 00 64 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_6 = "app.topvideosoft.com/ws/adsws.asmx?wsdl" wide //weight: 1
        $x_1_7 = {5c 00 73 00 79 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 00 25 00 73 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 22 00 61 00 73 00 70 00 63 00 68 00 65 00 63 00 6b 00 2e 00 65 00 78 00 65 00 22 00}  //weight: 1, accuracy: Low
        $x_1_8 = {75 00 70 00 64 00 61 00 74 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 76 00 65 00 72 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 00 72 00 6c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 1, accuracy: Low
        $x_1_9 = {73 00 68 00 6f 00 77 00 61 00 64 00 73 00 6c 00 6f 00 67 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5b 00 52 00 65 00 74 00 75 00 72 00 6e 00 4e 00 61 00 6d 00 65 00 3d 00 22 00 63 00 6c 00 69 00 63 00 6b 00 61 00 64 00 73 00 6c 00 6f 00 67 00 52 00 65 00 73 00 75 00 6c 00 74 00 22 00 5d 00}  //weight: 1, accuracy: Low
        $x_1_10 = {73 00 6f 00 6c 00 69 00 64 00 2d 00 63 00 6f 00 6d 00 6d 00 6f 00 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6f 00 70 00 74 00 69 00 6d 00 69 00 7a 00 65 00 72 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_11 = {73 00 79 00 73 00 76 00 65 00 72 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_12 = {68 00 69 00 64 00 65 00 5f 00 64 00 69 00 61 00 6c 00 6f 00 67 00 5f 00 61 00 64 00 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6c 00 61 00 73 00 74 00 5f 00 73 00 68 00 6f 00 77 00 5f 00 79 00 74 00 64 00}  //weight: 1, accuracy: Low
        $x_1_13 = {6e 00 65 00 77 00 76 00 65 00 72 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule SoftwareBundler_Win32_WinOptimizer_206677_3
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/WinOptimizer"
        threat_id = "206677"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "WinOptimizer"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\powermgr.exe" wide //weight: 1
        $x_1_2 = "\\vmnet.exe" wide //weight: 1
        $x_1_3 = "WindowsOptimizer" wide //weight: 1
        $x_1_4 = "last_web_ads" wide //weight: 1
        $x_1_5 = "ads_inteval_time=" wide //weight: 1
        $x_1_6 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = "app.topvideosoft.com/api_ajax.ashx?action=install" wide //weight: 1
        $x_1_8 = "app.topvideosoft.com/api_ajax.ashx?action=register" wide //weight: 1
        $x_1_9 = "app.download-server.org/ws/reportws.asmx?wsdl" wide //weight: 1
        $x_1_10 = "app.topvideosoft.com/ws/reportws.asmx?wsdl" wide //weight: 1
        $x_1_11 = {5c 00 77 00 69 00 6e 00 (66 00 69 00|70 00 68 00) 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_12 = "popupshow_interval_hours=" wide //weight: 1
        $x_1_13 = {6e 00 65 00 77 00 76 00 65 00 72 00 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule SoftwareBundler_Win32_WinOptimizer_206677_4
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/WinOptimizer"
        threat_id = "206677"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "WinOptimizer"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "unsubscribe vmnet notification" wide //weight: 1
        $x_1_2 = {5c 00 4f 00 70 00 74 00 69 00 6d 00 69 00 7a 00 65 00 72 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = "load_config.ini" wide //weight: 1
        $x_1_4 = "\\history.log" wide //weight: 1
        $x_1_5 = "server_name" wide //weight: 1
        $x_1_6 = ".file-mirror.org/unsubscribe.aspx?action=unshow&clientid=" wide //weight: 1
        $x_1_7 = "/navigate.aspx?cid=%s&uid=%s&src=%s&process=%s" wide //weight: 1
        $x_1_8 = "freevideotool.com/api_ajax.ashx?action=unshow&clientid=" wide //weight: 1
        $x_1_9 = {46 00 69 00 72 00 65 00 66 00 6f 00 78 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? 63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_10 = "right click here to unsubscribe ie helper" wide //weight: 1
        $x_1_11 = "app.topvideosoft.com/api_ajax.ashx?action=unshow&clientid=" wide //weight: 1
        $x_1_12 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 25 00 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 54 00 6f 00 70 00 69 00 63 00 20 00 25 00 73 00}  //weight: 1, accuracy: Low
        $x_1_13 = {67 00 65 00 74 00 61 00 64 00 73 00 69 00 6e 00 66 00 6f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5b 00 52 00 65 00 74 00 75 00 72 00 6e 00 4e 00 61 00 6d 00 65 00 3d 00 22 00 67 00 65 00 74 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 6c 00 69 00 73 00 74 00 52 00 65 00 73 00 75 00 6c 00 74 00 22 00 5d 00}  //weight: 1, accuracy: Low
        $x_1_14 = {83 7b 38 00 75 0a 83 7b 3c 00 75 04 33 c9 eb 02 b1 01 ba ?? ?? ?? ?? 8b c6 8b 18 ff 53 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}


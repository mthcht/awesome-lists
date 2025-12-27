rule TrojanDownloader_Win32_ValleyRat_CF_2147949369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ValleyRat.CF"
        threat_id = "2147949369"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 00 6f 00 73 00 00 00 68 00 00 00 74 00 00 00 74 70 00 00 3a 2f 2f 00 77 00 00 00 7a 67 6c 00 2e 00 00 00 79 6a 67 00 6c 6a 00 00 73 68 00 00 67 00 00 00 6f 76 2e 00 63 6e 3a 00 31 00 00 00 33 00 00 00 35 38 30 00 2f 00 00 00 64 00 00 00 65 6d 00 00 6f 2f 76 00 32 00 00 00 70 6e 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_ValleyRat_CF_2147949369_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ValleyRat.CF"
        threat_id = "2147949369"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 b8 b9 1a}  //weight: 1, accuracy: High
        $x_1_2 = {78 1f 20 7f}  //weight: 1, accuracy: High
        $x_1_3 = {62 34 89 5e}  //weight: 1, accuracy: High
        $x_1_4 = {73 80 48 06}  //weight: 1, accuracy: High
        $x_1_5 = {a5 f2 5c 70}  //weight: 1, accuracy: High
        $x_1_6 = "ntdl" ascii //weight: 1
        $x_1_7 = {cb 79 b5 0d}  //weight: 1, accuracy: High
        $x_1_8 = {c0 e9 18 15}  //weight: 1, accuracy: High
        $x_1_9 = {cf 2c f4 4f}  //weight: 1, accuracy: High
        $x_1_10 = {1b 16 ac 14}  //weight: 1, accuracy: High
        $x_1_11 = {b2 34 61 0f}  //weight: 1, accuracy: High
        $x_1_12 = {dc 87 83 0f}  //weight: 1, accuracy: High
        $x_1_13 = {da 50 2b 09}  //weight: 1, accuracy: High
        $x_1_14 = {c8 84 3a 31}  //weight: 1, accuracy: High
        $x_1_15 = {d7 7d 5e 78}  //weight: 1, accuracy: High
        $x_1_16 = {01 95 53 41}  //weight: 1, accuracy: High
        $x_1_17 = {9f 2d 40 26}  //weight: 1, accuracy: High
        $x_1_18 = "4&R3" ascii //weight: 1
        $x_10_19 = {43 0f b6 4c 1a 04 4c 8b 83 a0 00 00 00 b8 21 00 f3 20 49 ff c2 f7 e9 c1 fa 08 8b c2 c1 e8 1f 03 d0 b8 67 66 66 66 69 d2 c5 07 00 00 2b ca f7 ef 80 c1 36 43 30 0c 08 c1 fa 02 8b cf 8b c2 c1 e8 1f 03 d0 8d 04 92 03 c0 2b c8 f7 d9 48 1b c0 ff c7 49 ff c1 4c 23 d0 81 ff 0e d0 07 00}  //weight: 10, accuracy: High
        $x_5_20 = {48 63 42 20 48 63 4a 2c c7 44 24 20 57 73 32 5f 48 03 c8 c7 44 24 24 33 32 2e 64 66 c7 44 24 28 6c 6c 48 8d 44 4a 38 48 8d 4c 24 20}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_ValleyRat_CF_2147949369_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ValleyRat.CF"
        threat_id = "2147949369"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UnThreat" wide //weight: 1
        $x_1_2 = "K7TSecurity.exe" wide //weight: 1
        $x_1_3 = "Ad-watch.exe" wide //weight: 1
        $x_1_4 = "PSafeSysTray.exe" wide //weight: 1
        $x_1_5 = "BitDefender" wide //weight: 1
        $x_1_6 = "vsserv.exe" wide //weight: 1
        $x_1_7 = "remupd.exe" wide //weight: 1
        $x_1_8 = "rtvscan.exe" wide //weight: 1
        $x_1_9 = "ashDisp.exe" wide //weight: 1
        $x_1_10 = "avcenter.exe" wide //weight: 1
        $x_1_11 = "TMBMSRV.exe" wide //weight: 1
        $x_1_12 = "knsdtray.exe" wide //weight: 1
        $x_1_13 = "egui.exe" wide //weight: 1
        $x_1_14 = "Mcshield.exe" wide //weight: 1
        $x_1_15 = "avp.exe" wide //weight: 1
        $x_1_16 = "F-Secure" wide //weight: 1
        $x_1_17 = "avgwdsvc.exe" wide //weight: 1
        $x_1_18 = "AYAgent.aye" wide //weight: 1
        $x_1_19 = "V3Svc.exe" wide //weight: 1
        $x_1_20 = "acs.exe" wide //weight: 1
        $x_1_21 = "DR.WEB" wide //weight: 1
        $x_1_22 = "SPIDer.exe" wide //weight: 1
        $x_1_23 = "Comodo" wide //weight: 1
        $x_1_24 = "cfp.exe" wide //weight: 1
        $x_1_25 = "mssecess.exe" wide //weight: 1
        $x_1_26 = "QUHLPSVC.EXE" wide //weight: 1
        $x_1_27 = "RavMonD.exe" wide //weight: 1
        $x_1_28 = "KvMonXP.exe" wide //weight: 1
        $x_1_29 = "baiduSafeTray.exe" wide //weight: 1
        $x_1_30 = "BaiduSd.exe" wide //weight: 1
        $x_1_31 = "2345SafeTray.exe" wide //weight: 1
        $x_1_32 = "HipsTray.exe" wide //weight: 1
        $x_1_33 = "QQPCRTP.exe" wide //weight: 1
        $x_1_34 = "KSafeTray.exe" wide //weight: 1
        $x_1_35 = "kxetray.exe" wide //weight: 1
        $x_1_36 = "360sd.exe" wide //weight: 1
        $x_1_37 = "ZhuDongFangYu.exe" wide //weight: 1
        $x_1_38 = "360tray.exe" wide //weight: 1
        $x_1_39 = "360Safe.exe" wide //weight: 1
        $x_1_40 = "WxWork.exe" wide //weight: 1
        $x_1_41 = "WeChat.exe" wide //weight: 1
        $x_1_42 = "weixin.exe" wide //weight: 1
        $x_1_43 = "Telegram.exe" wide //weight: 1
        $x_1_44 = "DingTalk.exe" wide //weight: 1
        $x_1_45 = "DingTalkGov.exe" wide //weight: 1
        $x_1_46 = "ApateDNS" wide //weight: 1
        $x_1_47 = "Malwarebytes" wide //weight: 1
        $x_1_48 = "TCPEye" wide //weight: 1
        $x_1_49 = "TaskExplorer" wide //weight: 1
        $x_1_50 = "CurrPorts" wide //weight: 1
        $x_1_51 = "Metascan" wide //weight: 1
        $x_1_52 = "Wireshark" wide //weight: 1
        $x_1_53 = "Fiddler" wide //weight: 1
        $x_1_54 = "Capsa" wide //weight: 1
        $x_1_55 = "Ipdate" wide //weight: 1
        $x_1_56 = "IpdateSpecial" wide //weight: 1
        $x_5_57 = {c7 45 a8 30 cc ff 56 b8 98 d3 00 00 66 89 45 ac c7 45 ae d0 11 b2 ae c7 45 b2 00 a0 c9 08 66 c7 45 b6 fa 49 4c 89 74 24 70}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((50 of ($x_1_*))) or
            ((1 of ($x_5_*) and 45 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_ValleyRat_FG_2147959290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ValleyRat.FG!MTB"
        threat_id = "2147959290"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\WindowsFormsApp2.exe" ascii //weight: 1
        $x_1_2 = "C:\\DispHelper\\hr.exe" ascii //weight: 1
        $x_1_3 = "aHR0cDovLzEzNC4xMjIuMTYzLjIzMjo4ODg4L2Rvd24vbkJOWkxGQnlETW5O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


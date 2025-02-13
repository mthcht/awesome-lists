rule Trojan_Win32_Haradong_A_2147600638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Haradong.A"
        threat_id = "2147600638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Haradong"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Windows Media Player" ascii //weight: 10
        $x_10_2 = "Microsoft Visual Studio" ascii //weight: 10
        $x_10_3 = "\\taskmgr.exe" wide //weight: 10
        $x_10_4 = "svchost" wide //weight: 10
        $x_1_5 = "http://harada-x.hp.infoseek.co.jp/" wide //weight: 1
        $x_1_6 = "http://osaka0c.ninja.co.jp/" wide //weight: 1
        $x_1_7 = "http://denutaro.fc2.com/" wide //weight: 1
        $x_1_8 = "http://hmk2007isb.hp.infoseek.co.jp/" wide //weight: 1
        $x_1_9 = "http://simouth-1111tr.hp.infoseek.co.jp/" wide //weight: 1
        $x_1_10 = "http://harada2006.hp.infoseek.co.jp/" wide //weight: 1
        $x_1_11 = "http://yohimorisimangi.hp.infoseek.co.jp/" wide //weight: 1
        $x_1_12 = "http://sakamoto-sinji.hp.infoseek.co.jp/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


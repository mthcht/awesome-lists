rule Trojan_Win32_Msidebar_A_2147651355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Msidebar.A"
        threat_id = "2147651355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Msidebar"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d3 50 68 ?? ?? ?? ?? ff d7 8b d0 8d 4d dc ff d3 50 8b 4e ?? 51 ff d7}  //weight: 2, accuracy: Low
        $x_2_2 = {26 00 75 00 73 00 72 00 5f 00 67 00 75 00 62 00 75 00 6e 00 3d 00 [0-4] 26 00 73 00 65 00 72 00 69 00 61 00 6c 00 6e 00 6f 00 3d 00}  //weight: 2, accuracy: Low
        $x_2_3 = "execute.php?m_origin=" wide //weight: 2
        $x_1_4 = "&Pid=stinfomation" wide //weight: 1
        $x_1_5 = "&Pid=quickfindwd" wide //weight: 1
        $x_1_6 = "Msidebar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Msidebar_B_2147661722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Msidebar.B"
        threat_id = "2147661722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Msidebar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 75 00 73 00 72 00 5f 00 67 00 75 00 62 00 75 00 6e 00 3d 00 [0-4] 26 00 73 00 65 00 72 00 69 00 61 00 6c 00 6e 00 6f 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "execute.php?m_origin=" wide //weight: 1
        $x_1_3 = "&Pid=cwinsearch" wide //weight: 1
        $x_1_4 = "Msidebar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Msidebar_C_2147662270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Msidebar.C"
        threat_id = "2147662270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Msidebar"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isearchsrv.FileDownloader" ascii //weight: 1
        $x_1_2 = "isearchsrvplus\\turl" wide //weight: 1
        $x_1_3 = "Timer1=IEKill=SendMsg=" wide //weight: 1
        $x_1_4 = "Ssurlcnt" wide //weight: 1
        $x_1_5 = "popdown" wide //weight: 1
        $x_1_6 = "call_ad_keyword" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Msidebar_C_2147662270_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Msidebar.C"
        threat_id = "2147662270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Msidebar"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Msidebar" wide //weight: 5
        $x_1_2 = "/shopping.naver.com/" wide //weight: 1
        $x_1_3 = "/shopping.nate.com/" wide //weight: 1
        $x_1_4 = "/shopping.daum.net/" wide //weight: 1
        $x_1_5 = "/shopping.yahoo.co.kr/" wide //weight: 1
        $x_1_6 = "&usr_gubun=" wide //weight: 1
        $x_1_7 = "execute.php?m_origin=" wide //weight: 1
        $x_1_8 = "dns_yh_advertise" wide //weight: 1
        $x_1_9 = "\\SOFTWARE\\rpbottom" wide //weight: 1
        $x_1_10 = "Nothing to download!" wide //weight: 1
        $x_1_11 = "Authorization failed!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Msidebar_D_2147663233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Msidebar.D"
        threat_id = "2147663233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Msidebar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 75 00 73 00 72 00 5f 00 67 00 75 00 62 00 75 00 6e 00 3d 00 [0-4] 26 00 73 00 65 00 72 00 69 00 61 00 6c 00 6e 00 6f 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "execute.php?m_origin=" wide //weight: 1
        $x_1_3 = "&Pid=neowinsearch" wide //weight: 1
        $x_1_4 = "CompanyName  XP PLUS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


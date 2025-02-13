rule TrojanDownloader_Win32_Fundoyoo_A_2147624934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fundoyoo.A"
        threat_id = "2147624934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fundoyoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Microsoft\\id.txt" ascii //weight: 10
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_3 = "http://boscumix.com/optima/index.php" ascii //weight: 10
        $x_10_4 = {6a 00 6a 00 68 ?? ?? 40 00 8b cb ba 00 04 00 00 33 c0 e8 ?? ?? ff ff 6a 00 6a 00 68 ?? ?? 40 00 8b cb ba 00 04 00 00 33 c0 e8 ?? ?? ff ff 6a 00 6a 00 68 ?? ?? 40 00 8b cb ba 00 04 00 00 33 c0 e8 ?? ?? ff ff 6a 00 6a 00 68 ?? ?? 40 00 8b cb ba 00 04 00 00 33 c0 e8 ?? ?? ff ff 6a 00 6a 00 68 ?? ?? 40 00 8b cb ba 00 04 00 00 33 c0 e8 ?? ?? ff ff 6a 00}  //weight: 10, accuracy: Low
        $x_1_5 = "Mozilla/4.0 (compatible; MSIE 5.0; Windows 2000) Opera 6.03 [en]" ascii //weight: 1
        $x_1_6 = "Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)" ascii //weight: 1
        $x_1_7 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)" ascii //weight: 1
        $x_1_8 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.4.154.25 Safari/525.19 " ascii //weight: 1
        $x_1_9 = "Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)" ascii //weight: 1
        $x_1_10 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)" ascii //weight: 1
        $x_1_11 = "Mozilla/5.0 (compatible; Konqueror/3.5; Linux 2.6.15-1.2054_FC5; X11; i686; en_US) KHTML/3.5.4 (like Gecko)" ascii //weight: 1
        $x_1_12 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.8.1.19) Gecko/20081201 Firefox/2.0.0.19 " ascii //weight: 1
        $x_1_13 = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2" ascii //weight: 1
        $x_1_14 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; WOW64; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.21022; .NET CLR 3.5.30729; .NET CLR 3.0.30618)" ascii //weight: 1
        $x_1_15 = "\\tmp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Price_A_2147597984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Price.A"
        threat_id = "2147597984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Price"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "file.spymedic.co.kr/archive/CabUse.dll" ascii //weight: 1
        $x_1_2 = "ax.theprice.co.kr/archive/svrcache_mini.cab" ascii //weight: 1
        $x_1_3 = "file.searchspy.co.kr/archive/SearchPackMini.dll" ascii //weight: 1
        $x_1_4 = "ax.theprice.co.kr" ascii //weight: 1
        $x_1_5 = "ax.spymedic.co.kr" ascii //weight: 1
        $x_1_6 = "ax.searchspy.co.kr" ascii //weight: 1
        $x_1_7 = "InternetReadFile" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_9 = "CreateDirectoryA" ascii //weight: 1
        $x_1_10 = "FindNextFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


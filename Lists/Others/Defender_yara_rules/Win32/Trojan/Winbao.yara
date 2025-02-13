rule Trojan_Win32_Winbao_2147643129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winbao"
        threat_id = "2147643129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winbao"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mstarwwsose.com" ascii //weight: 1
        $x_1_2 = "starsssprose.com" ascii //weight: 1
        $x_1_3 = "aobao.c" ascii //weight: 1
        $x_1_4 = "/browse/search_auction.htm" ascii //weight: 1
        $x_1_5 = "ForceRemove {ABCAE223-1278-7829-A43E-42D18BB79950} = s 'Windows Assistannt v." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


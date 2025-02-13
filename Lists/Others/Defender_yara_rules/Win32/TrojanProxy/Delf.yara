rule TrojanProxy_Win32_Delf_G_2147583856_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Delf.G"
        threat_id = "2147583856"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://blyabudu.info/png.exe" ascii //weight: 1
        $x_1_2 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 1
        $x_1_3 = "dnsapi.dll" ascii //weight: 1
        $x_1_4 = "&usenames=1&smartpic=1&rand=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Delf_I_2147584616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Delf.I"
        threat_id = "2147584616"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Update Viewer" ascii //weight: 1
        $x_1_2 = "\\RDPLicense\\svchost.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_4 = "FastMM Borland Edition " ascii //weight: 1
        $x_1_5 = "http://www.gooo.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Delf_AN_2147594774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Delf.AN"
        threat_id = "2147594774"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mail exchanger = " ascii //weight: 1
        $x_1_2 = "DnsRecordListFree" ascii //weight: 1
        $x_1_3 = "InternetCrackUrlA" ascii //weight: 1
        $x_1_4 = "nslookup <" ascii //weight: 1
        $x_1_5 = "png/png.exe" ascii //weight: 1
        $x_1_6 = "jpg/jpg.exe" ascii //weight: 1
        $x_1_7 = "chgif.exe" ascii //weight: 1
        $x_1_8 = "/cgi-script/repeaterm3.fcgi?v5" ascii //weight: 1
        $x_1_9 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:" ascii //weight: 1
        $x_1_10 = "ServicePackFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanProxy_Win32_Delf_AM_2147595750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Delf.AM"
        threat_id = "2147595750"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "charset=\"koi8-r\"" ascii //weight: 1
        $x_1_2 = "\\ServicePackFiles\\mm" ascii //weight: 1
        $x_1_3 = "nslookup <" ascii //weight: 1
        $x_1_4 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:" ascii //weight: 1
        $x_1_5 = "mail exchanger =" ascii //weight: 1
        $x_1_6 = "mm.pidar" ascii //weight: 1
        $x_1_7 = "RANDOM_PICTURE_ID_FOR_ATTACHMENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanProxy_Win32_Delf_W_2147598487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Delf.W"
        threat_id = "2147598487"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\\Dados de aplicativos\\Microsoft\\Address Book" ascii //weight: 3
        $x_3_2 = {ba 05 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 84 c0 74 ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 ?? ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 84 c0}  //weight: 3, accuracy: Low
        $x_3_3 = {05 00 00 00 48 45 41 44 20 00 00 00 ff ff ff ff 06 00 00 00 20 48 54 54 50 2f 00 00 ff ff ff ff 04 00 00 00 47 45 54 20 00 00 00 00 ff ff ff ff 05 00 00 00 50 4f 53 54 20 00 00 00 ff ff ff ff 08 00 00 00 4f 50 54 49 4f 4e 53 20 00 00 00 00 ff ff ff ff 06 00 00 00 54 52 41 43 45 20 00 00 ff ff ff ff 04 00 00 00 50 55 54 20 00 00 00 00 ff ff ff ff 08 00 00 00 43 4f 4e 4e 45 43 54 20}  //weight: 3, accuracy: High
        $x_1_4 = "[Binary - Size: %d bytes] (%.8x)" ascii //weight: 1
        $x_1_5 = {4f 70 65 6e 57 61 62 46 69 6c 65 [0-16] 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 [0-16] 4e 6f 6d 65 43 6f 6d 70 75 74 61 64 6f 72 [0-16] 44 65 6c 65 74 65 46 69 6c 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Delf_R_2147624427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Delf.R"
        threat_id = "2147624427"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = {62 65 62 65 2e 64 6c 6c [0-4] 53 74 61 72 74 48 6f 6f 6b}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\chungwanet" ascii //weight: 1
        $x_1_4 = "\\Program Files\\Internet Explorer\\data\\chungwanet\\c.pm" ascii //weight: 1
        $x_1_5 = "1/key1.dat" ascii //weight: 1
        $x_1_6 = "httpGetCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


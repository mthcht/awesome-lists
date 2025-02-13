rule TrojanDownloader_Win32_Gogogovb_A_2147682001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gogogovb.A"
        threat_id = "2147682001"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gogogovb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d9adyz93472kb63z521t6e80wqpi56znb16fya6im3dr3xwe" wide //weight: 1
        $x_1_2 = "GET /data/{aid}?cli=10&dat=snba&ver" wide //weight: 1
        $x_1_3 = "pfw|rfwsrv|rfwmain|KPFW32|calc|rfw" wide //weight: 1
        $x_1_4 = "\\drivers\\etc\\Hosts" wide //weight: 1
        $x_1_5 = {67 65 74 41 67 65 6e 74 00 00 00 00 73 73 00 00 67 6f 67 6f 67 6f 00 00 6d 79 5f 67 65 74}  //weight: 1, accuracy: High
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


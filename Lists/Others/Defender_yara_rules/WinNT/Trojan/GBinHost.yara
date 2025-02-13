rule Trojan_WinNT_GBinHost_A_2147666870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/GBinHost.A"
        threat_id = "2147666870"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "GBinHost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Programas\\GbPlugin" wide //weight: 2
        $x_2_2 = {00 00 70 00 64 00 69 00 73 00 74 00 00 00 63 00 65 00 66 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = "Windows\\system32\\drivers" wide //weight: 2
        $x_10_4 = {8b 45 0c 48 c6 03 01 89 7b 04 74 3d 48 74 32 48 74 27}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


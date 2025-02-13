rule Trojan_Win32_DarkLetoh_SA_2147740789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkLetoh.SA"
        threat_id = "2147740789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkLetoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IXP000.TMP\\srdfqm.exe" ascii //weight: 1
        $x_1_2 = "market.pwsmbx.com" ascii //weight: 1
        $x_1_3 = "/3W3s6/edgeside.php" ascii //weight: 1
        $x_1_4 = "winpt_n.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


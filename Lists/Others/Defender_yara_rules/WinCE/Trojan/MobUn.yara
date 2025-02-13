rule Trojan_WinCE_MobUn_A_2147643832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinCE/MobUn.A"
        threat_id = "2147643832"
        type = "Trojan"
        platform = "WinCE: Windows CE platform"
        family = "MobUn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\srvce.lnk" wide //weight: 1
        $x_1_2 = "\\Windows\\msservice.exe" wide //weight: 1
        $x_1_3 = "\\Windows\\srvupdater.exe" wide //weight: 1
        $x_1_4 = "http://mobileunit.ru/index.php?getstr=param" wide //weight: 1
        $x_1_5 = {5c 73 65 6e 64 73 65 72 76 69 63 65 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


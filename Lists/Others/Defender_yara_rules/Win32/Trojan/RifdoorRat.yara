rule Trojan_Win32_RifdoorRat_CAZW_2147844005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RifdoorRat.CAZW!MTB"
        threat_id = "2147844005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RifdoorRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.hellobetta.com/mall/flash/POPUP/1.php" ascii //weight: 1
        $x_1_2 = "http://www.aega.co.kr/mall/manual/parser/parser.php" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "Downloadexec success" ascii //weight: 1
        $x_1_5 = "AhnUpadate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


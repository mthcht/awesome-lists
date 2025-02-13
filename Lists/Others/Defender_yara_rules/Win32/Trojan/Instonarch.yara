rule Trojan_Win32_Instonarch_A_2147680310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Instonarch.A"
        threat_id = "2147680310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Instonarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Nullsoft Install System v" ascii //weight: 10
        $x_10_2 = "\\Registry.dll" ascii //weight: 10
        $x_10_3 = "\\inetc.dll" ascii //weight: 10
        $x_10_4 = "www.installmonetizer.com" ascii //weight: 10
        $x_10_5 = "/SILENT" ascii //weight: 10
        $x_10_6 = {69 74 65 6d 69 64 3d [0-2] 26 70 75 62 69 64 3d}  //weight: 10, accuracy: Low
        $x_2_7 = "/trackstats.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


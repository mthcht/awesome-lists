rule Trojan_Win32_XllDownloader_A_2147812992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XllDownloader.A!ibt"
        threat_id = "2147812992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XllDownloader"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "packed:jack" ascii //weight: 1
        $x_1_2 = "packed:detail" ascii //weight: 1
        $x_1_3 = "packed:udexcel" ascii //weight: 1
        $x_1_4 = "packed:w6cjv" ascii //weight: 1
        $x_1_5 = "packed:josh" ascii //weight: 1
        $x_1_6 = "packed:jvg60l7iue" ascii //weight: 1
        $x_1_7 = "packed:jask" ascii //weight: 1
        $x_1_8 = "packed:resolution" ascii //weight: 1
        $x_1_9 = "packed:A0MT69D1E" ascii //weight: 1
        $x_10_10 = "exceldna.xll" ascii //weight: 10
        $x_10_11 = "xlautoopen" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Retliften_B_2147783052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Retliften.B"
        threat_id = "2147783052"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Retliften"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%s\\netfilter.sys" ascii //weight: 10
        $x_1_2 = "c.xalm" ascii //weight: 1
        $x_1_3 = "configure.xalm" ascii //weight: 1
        $x_10_4 = {72 65 67 69 6e 69 00}  //weight: 10, accuracy: High
        $x_10_5 = "http://45.113.202.180" ascii //weight: 10
        $x_10_6 = "http://110.42.4.180" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Retliften_C_2147783059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Retliften.C"
        threat_id = "2147783059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Retliften"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%s\\netfilter.sys" ascii //weight: 10
        $x_1_2 = "c.xalm" ascii //weight: 1
        $x_1_3 = "configure.xalm" ascii //weight: 1
        $x_10_4 = {72 65 67 69 6e 69 00}  //weight: 10, accuracy: High
        $x_10_5 = "atsv2,.=5)790/;05(9;1367" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


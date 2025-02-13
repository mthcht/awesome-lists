rule SoftwareBundler_Win32_MediaPass_152782_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/MediaPass"
        threat_id = "152782"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "MediaPass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Software\\AppDataLow\\HavingFunOnline" ascii //weight: 50
        $x_2_2 = "/usr/getgeoipinfo.php?gup=" ascii //weight: 2
        $x_2_3 = "/usr/register_svc.php?gup=" ascii //weight: 2
        $x_1_4 = "{SearchTerms}" ascii //weight: 1
        $x_1_5 = "<key>HomePage</key>" ascii //weight: 1
        $x_1_6 = "download.dymanet.com" ascii //weight: 1
        $x_1_7 = "bignetdaddy.com" ascii //weight: 1
        $x_1_8 = "download.trueads." ascii //weight: 1
        $n_100_9 = "register@havingfunonline.com" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_50_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


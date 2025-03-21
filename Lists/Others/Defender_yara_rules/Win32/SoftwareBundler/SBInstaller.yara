rule SoftwareBundler_Win32_SBInstaller_223443_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/SBInstaller"
        threat_id = "223443"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "SBInstaller"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "www-installsuccess.com" wide //weight: 10
        $x_10_2 = ".netdna-ssl.com/" wide //weight: 10
        $x_10_3 = "SECONDSTAGE" wide //weight: 10
        $x_1_4 = "/install.ashx?id=%s&fn=%s" wide //weight: 1
        $x_1_5 = "CInstallerUtils::" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_SBInstaller_223443_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/SBInstaller"
        threat_id = "223443"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "SBInstaller"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s /SECONDSTAGE /Mutex=%s /PIXGUID=%s" wide //weight: 1
        $x_1_2 = "/install.ashx?id=%s&fn=%s" wide //weight: 1
        $x_1_3 = "%%PingDomain%%/%d" wide //weight: 1
        $x_1_4 = "Set and keep www-searches.com my default search and homepage" wide //weight: 1
        $x_1_5 = {54 00 53 00 4d 00 74 00 78 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "/S /MAG=%s /INSTALL /dir=%s /products=%s" wide //weight: 1
        $x_1_7 = "/S /SCHEDULE /MAG=%s /pn=%s /pixGuid=%s /sub=%s /Reason=%s" wide //weight: 1
        $x_1_8 = "/install.ashx?mv=1&id=%s&fn=%s" wide //weight: 1
        $x_1_9 = "Set and keep www-searching my default search and homepage" wide //weight: 1
        $x_2_10 = "http://%%PingRtt%%/t.ashx" wide //weight: 2
        $x_2_11 = "PINGRTT" wide //weight: 2
        $x_2_12 = "SENO*FINISH" wide //weight: 2
        $x_2_13 = "OCApi::HideOffer" wide //weight: 2
        $x_1_14 = "CInstallerUtils::init" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


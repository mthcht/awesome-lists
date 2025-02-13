rule SoftwareBundler_Win32_OneClickDownloader_200292_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/OneClickDownloader"
        threat_id = "200292"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "OneClickDownloader"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "1ClickDownloader" ascii //weight: 3
        $x_3_2 = "YontooIEClient.dll" ascii //weight: 3
        $x_7_3 = ", I agree to the Yontoo privacy policy && terms of service." ascii //weight: 7
        $x_7_4 = "http://www.yontoo.com/PrivacyPolicy.aspx" ascii //weight: 7
        $x_9_5 = "DropDownDeals is a feature of Yontoo, a browser add-on that enhance sites with various features. Along with DropDownDeals, Eas" ascii //weight: 9
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


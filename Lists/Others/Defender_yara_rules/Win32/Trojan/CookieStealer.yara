rule Trojan_Win32_CookieStealer_2147752375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CookieStealer!MSR"
        threat_id = "2147752375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CookieStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://fasterpdfinstall.xyz:10000/cookie" ascii //weight: 3
        $x_1_2 = "open chrom's cookie file" ascii //weight: 1
        $x_1_3 = "open firefox's cookie file " ascii //weight: 1
        $x_1_4 = "instagram cookie" ascii //weight: 1
        $x_1_5 = "Microsoft\\Windows\\Cookies" wide //weight: 1
        $x_1_6 = "SELECT * FROM cookies" ascii //weight: 1
        $x_1_7 = "CHCookie.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


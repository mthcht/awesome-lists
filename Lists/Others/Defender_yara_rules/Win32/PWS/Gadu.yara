rule PWS_Win32_Gadu_A_2147640918_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gadu.gen!A"
        threat_id = "2147640918"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gadu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Product   : PassTool" ascii //weight: 2
        $x_3_2 = "Copyright : by maSs [c4f]" ascii //weight: 3
        $x_1_3 = "a z Gadu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Gadu_J_2147654694_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gadu.J"
        threat_id = "2147654694"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gadu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GG Number :" ascii //weight: 1
        $x_1_2 = "\\Gadu-Gadu 10\\" ascii //weight: 1
        $x_1_3 = "Apple Computer\\Preferences\\keychain.plist" ascii //weight: 1
        $x_1_4 = "\\Opera\\Opera\\wand.dat" ascii //weight: 1
        $x_1_5 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_6 = "SELECT * FROM logins LIMIT 1 OFFSET" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


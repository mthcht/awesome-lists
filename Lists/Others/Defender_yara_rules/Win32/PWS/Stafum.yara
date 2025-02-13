rule PWS_Win32_Stafum_A_2147687991_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stafum.A"
        threat_id = "2147687991"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stafum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/chrome_zakho.js" wide //weight: 1
        $x_1_2 = "109326740/open_site.txt" wide //weight: 1
        $x_1_3 = {65 00 6d 00 61 00 69 00 6c 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 70 00 61 00 73 00 73 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 70 00 72 00 6f 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = "SELECT * FROM cookies WHERE host_key=\"www.facebook.com\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


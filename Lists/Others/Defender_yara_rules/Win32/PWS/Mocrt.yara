rule PWS_Win32_Mocrt_A_2147730957_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mocrt.A!MTB"
        threat_id = "2147730957"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mocrt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM logins" ascii //weight: 1
        $x_1_2 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_3 = "\\MortyCrypter\\" wide //weight: 1
        $x_1_4 = "\\rdpwrap.ini" wide //weight: 1
        $x_1_5 = "Hey I'm Admin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


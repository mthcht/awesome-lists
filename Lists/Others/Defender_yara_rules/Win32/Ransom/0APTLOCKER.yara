rule Ransom_Win32_0APTLOCKER_DA_2147962814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/0APTLOCKER.DA!MTB"
        threat_id = "2147962814"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "0APTLOCKER"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "::: 0APT LOCKER :::" ascii //weight: 10
        $x_1_2 = "!!! ALL YOUR FILES ARE ENCRYPTED !!!" ascii //weight: 1
        $x_1_3 = "Wallpaper successfully change" ascii //weight: 1
        $x_1_4 = "Download and install Tor Browser:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_RatKeylogger_UV_2147796001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RatKeylogger.UV!MTB"
        threat_id = "2147796001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RatKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RatScreenModule" ascii //weight: 1
        $x_1_2 = "RatSoundModule" ascii //weight: 1
        $x_1_3 = "RatFileSystemModule" ascii //weight: 1
        $x_1_4 = "RatBrowserModule" ascii //weight: 1
        $x_1_5 = "RatKeyboardModule" ascii //weight: 1
        $x_1_6 = "RatMailModule" ascii //weight: 1
        $x_1_7 = "RatStarter\\Release Md\\Rat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_IckyCookie_C_2147977065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IckyCookie.C!MTB"
        threat_id = "2147977065"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IckyCookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Local\\Microsoft\\Credentials" ascii //weight: 1
        $x_1_2 = "\\AppData\\Roaming\\Microsoft\\Protect" ascii //weight: 1
        $x_1_3 = "chronium_browsers" ascii //weight: 1
        $x_1_4 = "gecko_browsers" ascii //weight: 1
        $x_1_5 = "browser_name" ascii //weight: 1
        $x_1_6 = "default/Login Data" ascii //weight: 1
        $x_1_7 = "browser_path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


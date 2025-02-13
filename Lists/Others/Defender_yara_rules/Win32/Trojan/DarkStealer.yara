rule Trojan_Win32_DarkStealer_ST_2147762352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkStealer.ST!MTB"
        threat_id = "2147762352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DarkStealer" ascii //weight: 1
        $x_1_2 = "Passwords_Edge.txt" ascii //weight: 1
        $x_1_3 = "Windows Web Password Credential" ascii //weight: 1
        $x_1_4 = "Windows Domain Certificate Credential" ascii //weight: 1
        $x_1_5 = "Windows Domain Password Credential" ascii //weight: 1
        $x_1_6 = "//setting[@name='Password']/value" ascii //weight: 1
        $x_1_7 = "\\Passwords_Mozilla.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


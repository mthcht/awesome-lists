rule Trojan_Win32_WebShellsMicro_A_2147954076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebShellsMicro.A"
        threat_id = "2147954076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebShellsMicro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pouya.asp" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


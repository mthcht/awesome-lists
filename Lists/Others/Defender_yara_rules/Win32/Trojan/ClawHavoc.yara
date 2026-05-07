rule Trojan_Win32_ClawHavoc_DC_2147968699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClawHavoc.DC!MTB"
        threat_id = "2147968699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClawHavoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c start msiexec /q /i http" wide //weight: 1
        $x_1_2 = "rem DeepSeek Claw" wide //weight: 1
        $x_1_3 = "cloudcraftshub.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


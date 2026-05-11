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

rule Trojan_Win32_ClawHavoc_GDK_2147968964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClawHavoc.GDK!MTB"
        threat_id = "2147968964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClawHavoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d b4 ff 75 b8 89 5d e8 32 d9 30 6d e9 0f b6 4d e2 30 4d ea 0f b6 4d e3 30 4d eb 8b 4d b0 89 45 ec 32 c1 30 6d ed 8d 4d bc 88 45 ec 0f b6 45 e6 30 45 ee 0f b6 45 e7 30 45 ef 8d 45 f0 50 8d 45 e8 88 5d e8 50 ff 75 a8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


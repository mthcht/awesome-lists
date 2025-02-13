rule Trojan_Win32_ShellcodeLauncher_RDA_2147901397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeLauncher.RDA!MTB"
        threat_id = "2147901397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeLauncher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 e0 8b f4 6a 40 68 00 10 00 00 8b 45 ec 50 6a 00 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


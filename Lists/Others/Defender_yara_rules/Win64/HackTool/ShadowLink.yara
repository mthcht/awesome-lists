rule HackTool_Win64_ShadowLink_B_2147835551_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ShadowLink.B!dha"
        threat_id = "2147835551"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ShadowLink"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "C:\\Users\\Public\\Defender\\Defender\\defender.exe" wide //weight: 100
        $x_100_2 = "--nt-service" wide //weight: 100
        $x_100_3 = "C:\\Users\\Public\\Defender\\Data\\Defender\\def" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Maloader_GMXN_2147966540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maloader.GMXN!MTB"
        threat_id = "2147966540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msbuild.exe" wide //weight: 1
        $x_1_2 = ".csproj" wide //weight: 1
        $x_1_3 = "/t:provepowershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


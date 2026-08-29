rule Trojan_Win32_DefenderTamper_YCS_2147977213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefenderTamper.YCS!MTB"
        threat_id = "2147977213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderTamper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wmic" wide //weight: 10
        $x_10_2 = "/namespace:\\\\root\\Microsoft\\Windows\\Defender" wide //weight: 10
        $x_10_3 = "MSFT_MpPreference" wide //weight: 10
        $x_10_4 = "Add ExclusionProcess=" wide //weight: 10
        $x_10_5 = "C:\\Windows\\System32" wide //weight: 10
        $x_1_6 = "\\cmd.exe" wide //weight: 1
        $x_1_7 = "\\clip.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


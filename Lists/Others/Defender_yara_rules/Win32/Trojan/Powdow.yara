rule Trojan_Win32_Powdow_HA_2147945900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.HA!MTB"
        threat_id = "2147945900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "132"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "% {[Char]$_})" wide //weight: 100
        $x_20_2 = "{$null = $_}" wide //weight: 20
        $x_10_3 = "[char]0x" wide //weight: 10
        $x_1_4 = "FromBase64String" wide //weight: 1
        $x_1_5 = "Get-Random" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


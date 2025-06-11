rule Trojan_Win32_PSObfus_BSA_2147943452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSObfus.BSA!MTB"
        threat_id = "2147943452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSObfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell $" wide //weight: 1
        $x_1_2 = ".replace(" wide //weight: 1
        $x_1_3 = "+ [char]" wide //weight: 1
        $x_1_4 = "[System.Convert]::FromBase64String( $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


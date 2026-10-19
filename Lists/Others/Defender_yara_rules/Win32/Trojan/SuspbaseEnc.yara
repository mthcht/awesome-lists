rule Trojan_Win32_SuspbaseEnc_A_2147980545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspbaseEnc.A!MTB"
        threat_id = "2147980545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspbaseEnc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "1..1 | % { [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String" wide //weight: 10
        $x_1_2 = "invoke-expression" wide //weight: 1
        $x_1_3 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


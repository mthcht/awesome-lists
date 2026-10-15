rule Trojan_Win32_SuspUrlConn_A_2147979645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspUrlConn.A!MTB"
        threat_id = "2147979645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspUrlConn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "22tuk.digital/took.php" wide //weight: 10
        $x_1_2 = "|iex" wide //weight: 1
        $x_1_3 = "|invoke-expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspUrlConn_B_2147980384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspUrlConn.B!MTB"
        threat_id = "2147980384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspUrlConn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/took.php" wide //weight: 10
        $x_10_2 = "https://tinyurl.com/y5ebzssa" wide //weight: 10
        $x_2_3 = "[Console]::In.ReadToEnd();" wide //weight: 2
        $x_1_4 = "|iex" wide //weight: 1
        $x_1_5 = "|invoke-expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


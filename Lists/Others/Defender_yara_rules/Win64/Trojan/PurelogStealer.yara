rule Trojan_Win64_PurelogStealer_AW_2147925939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PurelogStealer.AW!MTB"
        threat_id = "2147925939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PurelogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "focustask.exe" ascii //weight: 1
        $x_1_2 = "wextract.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


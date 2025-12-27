rule Trojan_MSIL_StrelaStealer_2147951589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StrelaStealer.MTH!MTB"
        threat_id = "2147951589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StrelaStealer"
        severity = "Critical"
        info = "MTH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StealerCrypt.exe" ascii //weight: 1
        $x_2_2 = "b77a5c561934e089" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


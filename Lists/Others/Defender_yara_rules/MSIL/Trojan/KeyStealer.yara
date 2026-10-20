rule Trojan_MSIL_KeyStealer_AMTB_2147980618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyStealer!AMTB"
        threat_id = "2147980618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hack11qr3_jpg" ascii //weight: 2
        $x_2_2 = "KeyStealer" ascii //weight: 2
        $x_1_3 = "Hack-Dayz.pdb" ascii //weight: 1
        $x_2_4 = "The Hack is Injected" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


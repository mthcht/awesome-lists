rule Trojan_MSIL_CapiStealer_A_2147956024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CapiStealer.A!AMTB"
        threat_id = "2147956024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CapiStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "91.223.75.96" ascii //weight: 2
        $x_1_2 = "S-1-5-32-544" ascii //weight: 1
        $x_1_3 = "VmDetector" ascii //weight: 1
        $x_1_4 = "persist1" ascii //weight: 1
        $x_1_5 = "killclient" ascii //weight: 1
        $x_1_6 = "ffprofile_safe.zip" ascii //weight: 1
        $x_1_7 = "CheckGuestRegistryStrong" ascii //weight: 1
        $x_1_8 = "CheckSmbiosMarkers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


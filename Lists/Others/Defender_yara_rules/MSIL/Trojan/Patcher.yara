rule Trojan_MSIL_Patcher_GPKG_2147966211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Patcher.GPKG!MTB"
        threat_id = "2147966211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Patcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "irm http" ascii //weight: 5
        $x_1_2 = "| iex" ascii //weight: 1
        $x_1_3 = "$5247bd39-5deb-4f14-af4b-9598a8544" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


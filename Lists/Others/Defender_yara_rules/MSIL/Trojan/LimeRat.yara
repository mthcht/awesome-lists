rule Trojan_MSIL_LimeRat_SBR_2147772915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LimeRat.SBR!MSR"
        threat_id = "2147772915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRat"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://github.com/LimerBoy/StormKitty" ascii //weight: 1
        $x_1_2 = "get_Target" ascii //weight: 1
        $x_1_3 = "DecodeDirectBits" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


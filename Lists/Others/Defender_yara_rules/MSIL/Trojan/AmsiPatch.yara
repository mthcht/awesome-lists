rule Trojan_MSIL_AmsiPatch_DA_2147921598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AmsiPatch.DA!MTB"
        threat_id = "2147921598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AmsiPatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Injecting VM hook code" ascii //weight: 100
        $x_1_2 = "SophosAmsiProvider.dll" ascii //weight: 1
        $x_1_3 = "com_antivirus.dll" ascii //weight: 1
        $x_1_4 = "Malwarebytes" ascii //weight: 1
        $x_1_5 = "[eax+ebx]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AmsiPatch_DB_2147921599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AmsiPatch.DB!MTB"
        threat_id = "2147921599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AmsiPatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 d3 0b 06 28 ?? ?? ?? ?? 0d 00 08 17 58 0c 08 06 20 2c 01 00 00 20 b8 0b 00 00 6f ?? ?? ?? ?? fe 04 13 04 11 04 2d d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


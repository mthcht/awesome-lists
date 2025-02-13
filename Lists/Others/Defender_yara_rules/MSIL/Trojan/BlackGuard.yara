rule Trojan_MSIL_BlackGuard_RDA_2147839392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlackGuard.RDA!MTB"
        threat_id = "2147839392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackGuard"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ac9ce92a-c785-4360-b1fd-19535bb5b679" ascii //weight: 1
        $x_1_2 = "IJSFIHB" ascii //weight: 1
        $x_1_3 = "BDIC.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BlackGuard_ABG_2147847157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlackGuard.ABG!MTB"
        threat_id = "2147847157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackGuard"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 40 1f 00 00 28 ?? ?? ?? 0a 20 f0 0f 00 00 28 ?? ?? ?? 0a 7e 01 00 00 04 7e 03 00 00 04 28 ?? ?? ?? 0a 0a 73 0e 00 00 0a 7e 02 00 00 04 06 6f ?? ?? ?? 0a 20 77 32 00 00 28 ?? ?? ?? 0a 73 10 00 00 0a 25}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "ekia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


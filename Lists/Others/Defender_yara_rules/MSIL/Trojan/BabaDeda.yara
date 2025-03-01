rule Trojan_MSIL_Babadeda_RDA_2147840120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Babadeda.RDA!MTB"
        threat_id = "2147840120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Babadeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WeyTroj" ascii //weight: 1
        $x_1_2 = "WeyT00x.tmp" wide //weight: 1
        $x_1_3 = "run00.exe" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_5 = "DisableRegistryTools" wide //weight: 1
        $x_1_6 = "System32\\WSLog.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Babadeda_PSRD_2147897152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Babadeda.PSRD!MTB"
        threat_id = "2147897152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Babadeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 28 cc 00 00 0a 0d 28 06 00 00 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 da 09 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 21 11 21 2c 0d 02 6f ?? ?? ?? 06 6f ?? ?? ?? 0a 00 00 00 17 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


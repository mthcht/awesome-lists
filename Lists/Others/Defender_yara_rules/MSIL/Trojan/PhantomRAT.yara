rule Trojan_MSIL_PhantomRAT_AHB_2147974468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomRAT.AHB!MTB"
        threat_id = "2147974468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = ":Stealer.Evasion.BrowserManager+<PrepareBrowsersAsync>d" ascii //weight: 30
        $x_20_2 = "5Stealer.Evasion.ProcessFreezer+<FreezeAndDoAsync>" ascii //weight: 20
        $x_10_3 = "PhantomRATKey" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_IronNetInjector_A_2147786447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/IronNetInjector.A!MTB"
        threat_id = "2147786447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IronNetInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Injecting assembly" ascii //weight: 3
        $x_3_2 = "Starting dotnet bootstrapper" ascii //weight: 3
        $x_3_3 = "Assembly injected" ascii //weight: 3
        $x_3_4 = "Injecting native library" ascii //weight: 3
        $x_3_5 = "NetInjector" ascii //weight: 3
        $x_3_6 = "GetFunctionAddressInTarget32ProcessWithShell" ascii //weight: 3
        $x_3_7 = "PeNet.Structures" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


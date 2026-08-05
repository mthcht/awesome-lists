rule Trojan_MSIL_SharpHound_VD_2147975316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SharpHound.VD!MTB"
        threat_id = "2147975316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SharpHound"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BloodHound" ascii //weight: 2
        $x_2_2 = "SharpHound" ascii //weight: 2
        $x_2_3 = "collectionmethods" ascii //weight: 2
        $x_2_4 = "LDAPPassword" ascii //weight: 2
        $x_2_5 = "InvokeSharpHound" ascii //weight: 2
        $x_1_6 = "NetSession" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


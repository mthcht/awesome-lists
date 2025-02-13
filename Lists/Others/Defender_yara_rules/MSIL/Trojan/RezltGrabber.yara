rule Trojan_MSIL_RezltGrabber_AYA_2147919625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RezltGrabber.AYA!MTB"
        threat_id = "2147919625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RezltGrabber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sniffer.zopz-api.com" wide //weight: 2
        $x_2_2 = "auth.zopz-api.com" wide //weight: 2
        $x_1_3 = "ZOPZ-SNIFF.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


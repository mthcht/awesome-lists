rule Trojan_MSIL_FakeAV_SG_2147908719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeAV.SG!MTB"
        threat_id = "2147908719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "plexiglass_Load" ascii //weight: 1
        $x_1_2 = "Total Antivirus.exe" ascii //weight: 1
        $x_1_3 = "\\temp\\Assembly.exe" wide //weight: 1
        $x_1_4 = "DisableAntiSpyware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


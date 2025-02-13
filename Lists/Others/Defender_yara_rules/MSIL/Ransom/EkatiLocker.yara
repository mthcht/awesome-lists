rule Ransom_MSIL_EkatiLocker_PAA_2147786942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/EkatiLocker.PAA!MTB"
        threat_id = "2147786942"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EkatiLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows" wide //weight: 1
        $x_1_2 = "ekati.RansomMessage.resources" ascii //weight: 1
        $x_1_3 = "BlockWebProtection" ascii //weight: 1
        $x_1_4 = "Files Encrypted" wide //weight: 1
        $x_1_5 = "taskkill.exe" wide //weight: 1
        $x_1_6 = "TestRansom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


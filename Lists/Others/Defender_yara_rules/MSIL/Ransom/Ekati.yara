rule Ransom_MSIL_Ekati_A_2147786955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ekati.A!MTB"
        threat_id = "2147786955"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ekati"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Successfully downloaded file from Tor site" ascii //weight: 1
        $x_1_2 = "adv firewall set opmode mode disable" ascii //weight: 1
        $x_1_3 = "Modifying firewall" ascii //weight: 1
        $x_1_4 = "onion.jpg" ascii //weight: 1
        $x_1_5 = "locker" ascii //weight: 1
        $x_1_6 = "logger" ascii //weight: 1
        $x_1_7 = "ruby" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Ekati_B_2147786956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ekati.B!MTB"
        threat_id = "2147786956"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ekati"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ekati for files to be encrypted" ascii //weight: 1
        $x_1_2 = "/c vssadmin.exe delete shadows" ascii //weight: 1
        $x_1_3 = "Web Protected blocked site successfully" ascii //weight: 1
        $x_1_4 = ".encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


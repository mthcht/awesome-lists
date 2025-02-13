rule Ransom_MSIL_VenusLocker_A_2147716859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/VenusLocker.A"
        threat_id = "2147716859"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenusLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Venusf" wide //weight: 1
        $x_1_2 = ".Venusp" wide //weight: 1
        $x_1_3 = "VenusLocker Team" wide //weight: 1
        $x_1_4 = "LockerPicBox" wide //weight: 1
        $x_1_5 = "Your are hacked" wide //weight: 1
        $x_1_6 = {5c 56 65 6e 75 73 4c 6f 63 6b 65 72 56 32 5c 56 65 6e 75 73 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 56 65 6e 75 73 4c 6f 63 6b 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_7 = {56 65 6e 75 73 4c 6f 63 6b 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_VenusLocker_A_2147716863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/VenusLocker.A!!VenusLocker.gen!A"
        threat_id = "2147716863"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenusLocker"
        severity = "Critical"
        info = "VenusLocker: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Venusf" ascii //weight: 1
        $x_1_2 = ".Venusp" ascii //weight: 1
        $x_1_3 = "VenusLocker Team" ascii //weight: 1
        $x_1_4 = "LockerPicBox" ascii //weight: 1
        $x_1_5 = "Your are hacked" ascii //weight: 1
        $x_1_6 = {5c 56 65 6e 75 73 4c 6f 63 6b 65 72 56 32 5c 56 65 6e 75 73 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 56 65 6e 75 73 4c 6f 63 6b 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_7 = {56 65 6e 75 73 4c 6f 63 6b 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


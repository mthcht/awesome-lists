rule TrojanSpy_MSIL_Sylonif_A_2147683515_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Sylonif.A"
        threat_id = "2147683515"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sylonif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wait a few seconds while scan your computer." wide //weight: 1
        $x_1_2 = "ftp://{0}:{1}/{2}/{3}" wide //weight: 1
        $x_1_3 = "Logfile of SystemInfoLOG" wide //weight: 1
        $x_1_4 = {46 74 70 55 70 6c 6f 61 64 46 69 6c 65 54 6f 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Sylonif_B_2147684271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Sylonif.B"
        threat_id = "2147684271"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sylonif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "112.216.7.180" wide //weight: 1
        $x_1_2 = "ftp://{0}:{1}/{2}/{3}" wide //weight: 1
        $x_1_3 = "BHADD N.A -/- N.A -/-" wide //weight: 1
        $x_1_4 = {46 74 70 55 70 6c 6f 61 64 46 69 6c 65 54 6f 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = "windowexesystemlog" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


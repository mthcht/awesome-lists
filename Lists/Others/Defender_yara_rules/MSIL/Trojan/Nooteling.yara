rule Trojan_MSIL_Nooteling_C_2147757771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nooteling.C!dha"
        threat_id = "2147757771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nooteling"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "6bc4d524-2083-40f9-892c-e3bc7efcdf05" ascii //weight: 3
        $x_1_2 = "https://api.onedrive.com/v1.0/shares/" wide //weight: 1
        $x_1_3 = "=FuMU^E2}5]_%@!+CD9nmB{pc38HoPLR" wide //weight: 1
        $x_1_4 = "Global\\MutexTestClass" wide //weight: 1
        $x_1_5 = "\\Library\\Library\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


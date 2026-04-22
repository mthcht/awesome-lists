rule Trojan_MSIL_Jaik_VDB_2147967555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jaik.VDB!MTB"
        threat_id = "2147967555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 0d 11 12 11 0d 72 0d 01 00 70 28 31 00 00 0a 7d 35 00 00 04 11 12 11 0d 72 39 01 00 70 28 31 00 00 0a 7d 36 00 00 04 11 12 7b 35 00 00 04 28 1a 00 00 06 11 12 7b 36 00 00 04}  //weight: 5, accuracy: High
        $x_1_2 = "CrimeOutput.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_ReaderDB_EBIV_2147949726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ReaderDB.EBIV!MTB"
        threat_id = "2147949726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReaderDB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 1d 13 05 2b c2 16 0a 18 13 05 2b bb 03 04 61 1f 2f 59 06 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 06 1f 7f 91 ?? ?? ?? ?? ?? 59 13 05 2b 9b 11 07 1f 7e 93 ?? ?? ?? ?? ?? 59 2b ef}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


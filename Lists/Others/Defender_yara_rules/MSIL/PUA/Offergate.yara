rule PUA_MSIL_Offergate_J_259985_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:MSIL/Offergate.J!ibt"
        threat_id = "259985"
        type = "PUA"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Offergate"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?version={0}&partner={1}&vid_exe=99&visit_id={2}&utm_source={3}&source=packed" wide //weight: 1
        $x_1_2 = "---BEGIN_BLOB---" wide //weight: 1
        $x_1_3 = {0a 13 09 12 09 fe 16 ?? 00 00 01 6f ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


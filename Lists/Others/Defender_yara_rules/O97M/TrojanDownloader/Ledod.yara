rule TrojanDownloader_O97M_Ledod_A_2147693773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ledod.A"
        threat_id = "2147693773"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ledod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QlwNDCszjrextremely = Vojzfeextremely(\"FnzcnZkextremely\", \"273420220f2f20283d313138372959664c12171a2a514a5704131c1e01090f2f0f144d0d35064a1d1a1509041604562f031b040b741b0d084b1b0150545c4b745e5c070f2e0a585a542e014d\")" ascii //weight: 1
        $x_1_2 = "cnOkRnmextremely = Asc(Mid$(EiNMLlUOStabscond, ((hzbiMCrtrzita Mod Len(EiNMLlUOStabscond)) + 1), 1))" ascii //weight: 1
        $x_1_3 = "ugDETqwintruder = ugDETqwintruder + Chr(mHCaKBikdabscond Xor cnOkRnmextremely)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


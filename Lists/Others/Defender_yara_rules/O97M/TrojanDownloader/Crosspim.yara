rule TrojanDownloader_O97M_Crosspim_A_2147723184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Crosspim.A"
        threat_id = "2147723184"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Crosspim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MacScript \"do shell script \"\"(curl -s" ascii //weight: 1
        $x_1_2 = "token=\" & Read(\"ID\")" ascii //weight: 1
        $x_1_3 = "Read(\"OF\") & \".pkg" ascii //weight: 1
        $x_1_4 = "ComputerName\") & vbNewLine & Environ(\"UserDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


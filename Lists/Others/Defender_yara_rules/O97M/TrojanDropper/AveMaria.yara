rule TrojanDropper_O97M_AveMaria_BAK_2147777180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/AveMaria.BAK!MTB"
        threat_id = "2147777180"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Static Sub DOCUMenT_opeN()" ascii //weight: 1
        $x_1_2 = "Call dfmzzkgEgITguBzVpee: End Sub" ascii //weight: 1
        $x_1_3 = "Call VBA.Shell$(rttrtrhthtryyy.OptionButtoffgfdgdfggggn1.GroupName, vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


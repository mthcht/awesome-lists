rule Trojan_MSIL_ArtemLoad_NR_2147912423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArtemLoad.NR!MTB"
        threat_id = "2147912423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Profiles Manager verssion backup all" ascii //weight: 1
        $x_1_2 = "BrowsersManagerDataSetTableAdapters" ascii //weight: 1
        $x_1_3 = "Morad DERHOURHI" ascii //weight: 1
        $x_1_4 = "ProfilsManagerGmail.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_Crysome_AMTB_2147964574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysome!AMTB"
        threat_id = "2147964574"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/create /tn \"CrysomeLoader\"" ascii //weight: 1
        $x_1_2 = "TCP CONNECTED! Sending client info.." ascii //weight: 1
        $x_1_3 = "Crysome.Client.Web.WebFileDownloader+<DownloadFile>" ascii //weight: 1
        $x_1_4 = "Crysome.Client.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


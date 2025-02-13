rule TrojanDownloader_MSIL_Fakare_A_2147722493_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Fakare.A!bit"
        threat_id = "2147722493"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fakare"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jddrtj.duckdns.org" wide //weight: 1
        $x_1_2 = "Windows_security.vbs" wide //weight: 1
        $x_1_3 = "svchosti.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


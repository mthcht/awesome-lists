rule TrojanDownloader_MSIL_Kryptik_RDD_2147837537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Kryptik.RDD!MTB"
        threat_id = "2147837537"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "/C ping 1.1.1.1 -n 2 -w 1000 > Nul & Del \"" wide //weight: 1
        $x_1_3 = "get_ExecutablePath" ascii //weight: 1
        $x_1_4 = "SharpConfigParser.dll" wide //weight: 1
        $x_1_5 = "dnlib.dll" wide //weight: 1
        $x_1_6 = "ga.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


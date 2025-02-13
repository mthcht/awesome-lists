rule TrojanDownloader_MSIL_Nanocrypt_2147764303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nanocrypt!MTB"
        threat_id = "2147764303"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Process" ascii //weight: 1
        $x_1_2 = "ProcessStartInfo" ascii //weight: 1
        $x_1_3 = "set_WindowStyle" ascii //weight: 1
        $x_1_4 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_5 = "set_FileName" ascii //weight: 1
        $x_1_6 = "set_Arguments" ascii //weight: 1
        $x_1_7 = "set_StartInfo" ascii //weight: 1
        $x_10_8 = "powershell.exe" wide //weight: 10
        $x_10_9 = "/c powershell" wide //weight: 10
        $x_10_10 = "-noexit -exec bypass -window 1 -enc" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


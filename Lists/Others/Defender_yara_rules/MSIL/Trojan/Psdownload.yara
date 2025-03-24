rule Trojan_MSIL_Psdownload_PGP_2147936852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Psdownload.PGP!MTB"
        threat_id = "2147936852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Psdownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "refs/heads/main/MasonRootkit.exe" ascii //weight: 1
        $x_4_2 = "Disable-Windows-Defender/main/source.bat" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


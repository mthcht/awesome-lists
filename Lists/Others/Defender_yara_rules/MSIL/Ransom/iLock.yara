rule Ransom_MSIL_iLock_SN_2147968911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/iLock.SN!MTB"
        threat_id = "2147968911"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "iLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All your data is encrypted!" wide //weight: 2
        $x_2_2 = "To decrypt write to email: " wide //weight: 2
        $x_2_3 = "5e18c5d2-d1e4-4426-82ff-7269bdb4b170" ascii //weight: 2
        $x_2_4 = "/C timeout /t 2 & del " wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


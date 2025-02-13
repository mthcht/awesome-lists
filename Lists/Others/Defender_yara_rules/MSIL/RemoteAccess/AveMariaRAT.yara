rule RemoteAccess_MSIL_AveMariaRAT_D_351512_0
{
    meta:
        author = "defender2yara"
        detection_name = "RemoteAccess:MSIL/AveMariaRAT.D!MTB"
        threat_id = "351512"
        type = "RemoteAccess"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Low"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 11 01 02 8e 69 5d 02 11 01 02 8e 69 5d 91 11 00 11 01 11 00 8e 69 5d 91 61 28 ?? 00 00 0a 02 11 01 17 58 02 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 38}  //weight: 2, accuracy: Low
        $x_1_2 = "GetExportedTypes" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


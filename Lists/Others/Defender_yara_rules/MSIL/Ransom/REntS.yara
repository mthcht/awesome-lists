rule Ransom_MSIL_REntS_SN_2147975033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/REntS.SN!MTB"
        threat_id = "2147975033"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic shadowcopy delete" wide //weight: 1
        $x_1_2 = "vssadmin delete shadows //all //quiet" wide //weight: 1
        $x_1_3 = "ransom_wallpaper.bmp" wide //weight: 1
        $x_1_4 = "Your files have been encrypted." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


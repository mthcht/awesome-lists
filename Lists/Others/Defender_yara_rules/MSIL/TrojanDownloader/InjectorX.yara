rule TrojanDownloader_MSIL_InjectorX_RDB_2147896726_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/InjectorX.RDB!MTB"
        threat_id = "2147896726"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rdqvmvc" ascii //weight: 1
        $x_1_2 = "Rvwbeenmnswsmihhjubg" ascii //weight: 1
        $x_1_3 = "Qhnxahhiucviyrgxcrqpewtj" ascii //weight: 1
        $x_1_4 = "d2485e62400e49205f286574889ce4b1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


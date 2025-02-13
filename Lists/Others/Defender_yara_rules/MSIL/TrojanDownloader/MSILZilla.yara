rule TrojanDownloader_MSIL_MSILZilla_RDB_2147839818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/MSILZilla.RDB!MTB"
        threat_id = "2147839818"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e0b538cd-d7bc-4dd2-af91-4e35a820c221" ascii //weight: 1
        $x_1_2 = "LimuxTool" ascii //weight: 1
        $x_1_3 = "Eiigzs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_MSILZilla_NIT_2147925283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/MSILZilla.NIT!MTB"
        threat_id = "2147925283"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vmwareservice" wide //weight: 2
        $x_2_2 = "VBoxService" wide //weight: 2
        $x_2_3 = "%systemdrive%" wide //weight: 2
        $x_1_4 = "vmtoolsd" wide //weight: 1
        $x_1_5 = "vmwaretray" wide //weight: 1
        $x_1_6 = "x64dbg" wide //weight: 1
        $x_1_7 = "fiddler" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_MSIL_SelfDel_AN_2147744211_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SelfDel.AN!MSR"
        threat_id = "2147744211"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SelfDel"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ConsoleApp2\\ConsoleApp2\\obj\\Release\\NetClient.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


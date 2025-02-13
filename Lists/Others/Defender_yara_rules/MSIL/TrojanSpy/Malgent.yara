rule TrojanSpy_MSIL_Malgent_MSG_2147828552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Malgent.MSG!MSR"
        threat_id = "2147828552"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malgent"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CymulateScreenShotTrojan.pdb" ascii //weight: 1
        $x_1_2 = "bitsadmin.exe /transfer \"Cymulate_%attack_id%\" %stager_link% \"%programdata_path%\\%file_to_download%" wide //weight: 1
        $x_1_3 = "iex ((New-Object net.webclient).DownloadString" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


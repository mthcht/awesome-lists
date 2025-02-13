rule TrojanSpy_MSIL_Rulervth_A_2147726556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Rulervth.A!bit"
        threat_id = "2147726556"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rulervth"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TH3RULER_KEY" wide //weight: 1
        $x_1_2 = "\\AppData\\Roaming\\Microsoft\\Windows\\CAM.dat" wide //weight: 1
        $x_1_3 = "/Webcam_Shots/" wide //weight: 1
        $x_1_4 = "LOGIN_DATA_DOWNLOAD_WORKER" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


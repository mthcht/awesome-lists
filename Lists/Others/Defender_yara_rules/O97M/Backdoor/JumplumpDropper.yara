rule Backdoor_O97M_JumplumpDropper_A_2147826199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:O97M/JumplumpDropper.A!dha"
        threat_id = "2147826199"
        type = "Backdoor"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "JumplumpDropper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "telling her about medicines for getting children, by talking to her" ascii //weight: 1
        $x_1_2 = "Whichever of the above causes a man may detect, he should endeavour to" ascii //weight: 1
        $x_1_3 = "In the same way a girl who is called by the name of one of the" ascii //weight: 1
        $x_1_4 = "property infringement, a defective or damaged disk or other medium, a" ascii //weight: 1
        $x_1_5 = "corrupt data, transcription errors, a copyright or other intellectual" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


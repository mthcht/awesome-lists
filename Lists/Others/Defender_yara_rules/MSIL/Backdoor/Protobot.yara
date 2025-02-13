rule Backdoor_MSIL_Protobot_A_2147726223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Protobot.A!bit"
        threat_id = "2147726223"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Protobot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "faqebook.blogspot.com.tr" wide //weight: 1
        $x_1_2 = "C:\\Temps\\sys.exe" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "winsearch.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


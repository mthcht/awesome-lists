rule Backdoor_MSIL_SmallSpyware_AAA_2147970532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SmallSpyware.AAA!AMTB"
        threat_id = "2147970532"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmallSpyware"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\Users\\dell\\Desktop\\scr\\scr\\obj\\x86\\Debug\\pdf.pdb" ascii //weight: 10
        $x_1_2 = "screenCapture" ascii //weight: 1
        $x_1_3 = "ScreenPath" ascii //weight: 1
        $x_1_4 = "Kill" ascii //weight: 1
        $x_1_5 = "UploadFile" ascii //weight: 1
        $x_1_6 = "http://plutoneverdie87.com/work/phto/phoup.php" wide //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_8 = "Error setting startup reg key for all users." wide //weight: 1
        $x_1_9 = "pdf.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


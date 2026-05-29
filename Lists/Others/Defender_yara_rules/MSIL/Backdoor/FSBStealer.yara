rule Backdoor_MSIL_FSBStealer_AAA_2147970530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/FSBStealer.AAA!AMTB"
        threat_id = "2147970530"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FSBStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "\\Updater\\CyberGun\\obj\\Release\\CyberGun.pdb" ascii //weight: 15
        $x_2_2 = "<logger>5__2" ascii //weight: 2
        $x_2_3 = "Logger" ascii //weight: 2
        $x_2_4 = "last_scan_time.dat" wide //weight: 2
        $x_2_5 = "https://api.telegram.org/bot" wide //weight: 2
        $x_2_6 = ">CyberGun.ResourceTracker.TelegramUploader+<SendFilesAsync>d__6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


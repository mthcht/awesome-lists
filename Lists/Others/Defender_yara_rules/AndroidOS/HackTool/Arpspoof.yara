rule HackTool_AndroidOS_Arpspoof_A_2147929230_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Arpspoof.A!MTB"
        threat_id = "2147929230"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Arpspoof"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killall arpspoof" ascii //weight: 1
        $x_1_2 = "ArpspoofService" ascii //weight: 1
        $x_1_3 = "Spoofing was interrupted" ascii //weight: 1
        $x_1_4 = "arpspoof/RootAccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


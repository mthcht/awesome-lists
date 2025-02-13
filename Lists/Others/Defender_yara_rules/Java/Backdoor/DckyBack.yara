rule Backdoor_Java_DckyBack_A_2147781625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/DckyBack.A!MTB"
        threat_id = "2147781625"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "DckyBack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thatcherclough/betterbackdoor/shell/HandleCommand" ascii //weight: 1
        $x_1_2 = "DuckyScript" ascii //weight: 1
        $x_1_3 = "\\keys.log" ascii //weight: 1
        $x_1_4 = "Enter victim's filepath of file to send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_O97M_Obfue_RPWD_2147819255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Obfue.RPWD!MTB"
        threat_id = "2147819255"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfue"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wafll st + \"\\\" + bb, accef34Decode(UserForm1.Label1), CByte(79), 0" ascii //weight: 1
        $x_1_2 = "Chr(32 Xor CByte(99)) + Chr(83 Xor CByte(105)) + Chr(48 Xor CByte(108)) + Chr(55 Xor CByte(98)) +" ascii //weight: 1
        $x_1_3 = "Chr(15 Xor CByte(108)) + Chr(1 Xor CByte(108)) + Chr(20 Xor CByte(100)) + Chr(76 Xor CByte(46)) + Chr(95 Xor CByte(52)) " ascii //weight: 1
        $x_1_4 = "Chr(46 Xor CByte(114)) + Chr(53 Xor CByte(101)) + Chr(6 Xor CByte(115)) + Chr(55 Xor CByte(85)) + Chr(48 Xor CByte(92)) + Chr(83 Xor CByte(58)) + Chr(32 Xor CByte(67))" ascii //weight: 1
        $x_1_5 = "+ Chr(0 Xor CByte(54)) + Chr(95 Xor CByte(107)) + Chr(76 Xor CByte(98)) + Chr(20 Xor CByte(112)) + Chr(1 Xor CByte(109)) + Chr(15 Xor CByte(99))" ascii //weight: 1
        $x_1_6 = "Chr(6 Xor CByte(117)) + Chr(53 Xor CByte(80)) + Chr(46 Xor CByte(92)) + Chr(0 Xor CByte(115))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


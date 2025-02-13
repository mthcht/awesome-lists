rule Trojan_Win32_TreasureHunter_A_2147730656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TreasureHunter.A"
        threat_id = "2147730656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TreasureHunter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/gate.php" ascii //weight: 1
        $x_1_2 = "\\treasureHunter\\Release\\treasureHunter.pdb" ascii //weight: 1
        $x_1_3 = "cmdLineDecrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TreasureHunter_B_2147896161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TreasureHunter.B!MTB"
        threat_id = "2147896161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TreasureHunter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Treasure Hunter" wide //weight: 2
        $x_2_2 = "Content-Type: application/x-www-form-urlencoded" wide //weight: 2
        $x_2_3 = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)" ascii //weight: 2
        $x_2_4 = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729)" ascii //weight: 2
        $x_2_5 = "successfully sent the dumps" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


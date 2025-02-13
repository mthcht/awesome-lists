rule Backdoor_MSIL_Bladabhindi_J_2147729260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabhindi.J!MTB"
        threat_id = "2147729260"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabhindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "011010010110111001101010010100100111010101101110" wide //weight: 1
        $x_1_2 = "01010011 01100001 01101110 01100100 01100010 01101111 01111000 01101001 01100101" wide //weight: 1
        $x_1_3 = "01110011 01110110 01100011 01101000 01101111 01110011 01110100" wide //weight: 1
        $x_1_4 = "01100100 01101100 01101100 01101000 01101111 01110011 01110100" wide //weight: 1
        $x_1_5 = "01110010 01110101 01101110 01100100 01101100 01101100" wide //weight: 1
        $x_1_6 = "01000100 01101111 01110111 01101110 01101100 01101111 01100001 01100100 01000100 01100001 01110100 01100001" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabhindi_K_2147730020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabhindi.K!MTB"
        threat_id = "2147730020"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabhindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "installutil /logtoconsole=false /logfile= /u \" & Chrw(34) & \"%path%\" & Chrw(34)" wide //weight: 1
        $x_1_3 = "%DirInject%" wide //weight: 1
        $x_1_4 = "%FileInject%" wide //weight: 1
        $x_1_5 = "%HideWindow%" wide //weight: 1
        $x_1_6 = "%Persistence%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


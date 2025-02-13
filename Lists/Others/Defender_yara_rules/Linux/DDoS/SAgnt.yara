rule DDoS_Linux_SAgnt_B_2147828136_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/SAgnt.B!xp"
        threat_id = "2147828136"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Soket Olusturma Hatasi%s" ascii //weight: 1
        $x_1_2 = "Set hata ...%d" ascii //weight: 1
        $x_1_3 = "isaret: %d" ascii //weight: 1
        $x_1_4 = "Ortalama paket / saniye: %d" ascii //weight: 1
        $x_1_5 = "Port Hatasi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Linux_SAgnt_A_2147828990_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/SAgnt.A!xp"
        threat_id = "2147828990"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "12CDDosUDPTask" ascii //weight: 1
        $x_1_2 = "12CDDosSynTask" ascii //weight: 1
        $x_1_3 = "11CDDosCCTask" ascii //weight: 1
        $x_1_4 = "syn ddos task finished" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DDoS_Linux_SAgnt_B_2147835104_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/SAgnt.B!MTB"
        threat_id = "2147835104"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AttackWorker" ascii //weight: 1
        $x_1_2 = "DealwithDDoS" ascii //weight: 1
        $x_1_3 = "dnsAmp" ascii //weight: 1
        $x_1_4 = "flood.c" ascii //weight: 1
        $x_1_5 = "udp_checksum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Linux_SAgnt_C_2147901391_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/SAgnt.C!MTB"
        threat_id = "2147901391"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(crontab -l 2>/dev/null; echo \"@reboot %s\") | crontab" ascii //weight: 1
        $x_1_2 = "We are killing %s due to it having what is most " ascii //weight: 1
        $x_1_3 = "multi-user.target" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


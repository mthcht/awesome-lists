rule Ransom_Linux_NoEscape_A_2147895901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/NoEscape.A!MTB"
        threat_id = "2147895901"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "NoEscape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW_TO_RECOVER_FILES.txt" ascii //weight: 1
        $x_1_2 = "imgpayld.tgz" ascii //weight: 1
        $x_1_3 = "calling ioctlsocket" ascii //weight: 1
        $x_1_4 = "note_text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Linux_PAMBackdoor_A_2147949118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PAMBackdoor.A!MTB"
        threat_id = "2147949118"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PAMBackdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 55 e8 48 8b 45 f8 48 01 d0 0f b6 08 48 8b 45 f8 ba 00 00 00 00 48 f7 75 f0 48 8b 45 e0 48 01 d0 0f b6 10 48 8b 75 e8 48 8b 45 f8 48 01 f0 31 ca 88 10 48 83 45 f8 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_PAMBackdoor_B_2147949119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PAMBackdoor.B!MTB"
        threat_id = "2147949119"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PAMBackdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "decrypt_phrase" ascii //weight: 2
        $x_2_2 = "init_phrases" ascii //weight: 2
        $x_1_3 = "o_pam_authenticate" ascii //weight: 1
        $x_1_4 = "o_pam_open_session" ascii //weight: 1
        $x_1_5 = "sshd[%d]" ascii //weight: 1
        $x_1_6 = "/proc/%s/cmdline" ascii //weight: 1
        $x_1_7 = "/proc/%s/environ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


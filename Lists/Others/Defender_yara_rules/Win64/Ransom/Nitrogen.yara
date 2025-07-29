rule Ransom_Win64_Nitrogen_A_2147947697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nitrogen.A!MTB"
        threat_id = "2147947697"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nitrogen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Take this seriously, this is not a joke! Your company network are encrypted and" ascii //weight: 1
        $x_1_2 = "your data has been stolen and downloaded to our servers. Ignoring this message" ascii //weight: 1
        $x_1_3 = ".onion" ascii //weight: 1
        $x_1_4 = "Install Tor Browser" ascii //weight: 1
        $x_1_5 = "_READ_ME_.TXT" ascii //weight: 1
        $x_1_6 = ".NITROGEN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


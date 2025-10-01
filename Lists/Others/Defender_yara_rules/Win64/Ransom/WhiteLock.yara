rule Ransom_Win64_WhiteLock_BA_2147953707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WhiteLock.BA!MTB"
        threat_id = "2147953707"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WhiteLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your systems have been compromised, and all important information has been extracted and encrypted." ascii //weight: 1
        $x_1_2 = "What happens if you don't pay the ransom" ascii //weight: 1
        $x_1_3 = "All your information will be sold and published on the dark web" ascii //weight: 1
        $x_1_4 = "Tor Browser" ascii //weight: 1
        $x_1_5 = ".onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


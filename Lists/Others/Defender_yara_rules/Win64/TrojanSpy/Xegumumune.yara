rule TrojanSpy_Win64_Xegumumune_AXU_2147927658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Xegumumune.AXU!MTB"
        threat_id = "2147927658"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Xegumumune"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "209.151.151.172/media/itemmedia" ascii //weight: 4
        $x_3_2 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn" ascii //weight: 3
        $x_2_3 = "\\AppData\\Roaming\\Exodus\\exodus.wallet" ascii //weight: 2
        $x_5_4 = "curl -X POST -H \"Content-Type: application/json\" -k https://209.151.151.172/timetrack/add -d" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win64_Xegumumune_ARA_2147952225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Xegumumune.ARA!MTB"
        threat_id = "2147952225"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Xegumumune"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Keystroke & Screenshot Report" ascii //weight: 2
        $x_2_2 = "send_data_with_screenshot" ascii //weight: 2
        $x_2_3 = "payload_json" ascii //weight: 2
        $x_2_4 = "/KeyLogger" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


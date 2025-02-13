rule Spammer_Win32_Morphisil_A_2147720123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Morphisil.A"
        threat_id = "2147720123"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Morphisil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/SuccessMails?CampaignNum=%ld" ascii //weight: 1
        $x_1_2 = "Downloading maillist..." ascii //weight: 1
        $x_1_3 = "#fromalias" ascii //weight: 1
        $x_1_4 = "{%%RND_BASE64:%ld%%}" ascii //weight: 1
        $x_1_5 = "Subject: {%SUBJECT%}" ascii //weight: 1
        $x_1_6 = "{%BEGIN_MORPHIMAGE%}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


rule Ransom_Win64_HiddenTear_NR_2147964344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HiddenTear.NR!MTB"
        threat_id = "2147964344"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 8c 24 88 00 00 00 ba 10 00 00 00 89 c5 0f b6 f0 0f b6 fc c1 e8 18 c1 ed 10 89 74 24 30 41 89 c1 44 0f b6 c5 89 7c 24 28 bd 00 02 00 00 44 89 44 24 20}  //weight: 2, accuracy: High
        $x_1_2 = {41 89 c4 89 c2 e9 85 00 00 00 80 fa 18 0f 85 81 00 00 00 48 8b 7c 24 60 49 8d 74 0e 02 0f b6 cb 41 bf 01 00 00 00 f3 a4 48 8b 4c 24 60}  //weight: 1, accuracy: High
        $x_1_3 = "Connected to C&C server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_HiddenTear_VDA_2147972366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HiddenTear.VDA!MTB"
        threat_id = "2147972366"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://discord.com/api/webhooks/" wide //weight: 2
        $x_1_2 = "_Contact_us_telegram_" wide //weight: 1
        $x_2_3 = "vssadmin delete shadows /all /quiet" wide //weight: 2
        $x_2_4 = "ExecutionPolicy Bypass" wide //weight: 2
        $x_1_5 = "encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


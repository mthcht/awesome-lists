rule Ransom_Win64_Spora_MX_2147957025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Spora.MX!MTB"
        threat_id = "2147957025"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Spora"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files are encrypted" wide //weight: 1
        $x_5_2 = "vssadmin.exe delete shadows /all /quiet" wide //weight: 5
        $x_1_3 = "AVKill" wide //weight: 1
        $x_1_4 = "Telegram" wide //weight: 1
        $x_1_5 = "Encryption complete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

